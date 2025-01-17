from scapy.all import ARP, Ether, srp, IP, TCP, sr1
import netifaces
from colorama import Fore, Style
import sys
import requests
import socket
import re
from datetime import datetime

# Try importing optional dependencies
try:
    from mac_vendor_lookup import MacLookup
    MAC_LOOKUP_AVAILABLE = True
except ImportError:
    MAC_LOOKUP_AVAILABLE = False
    print(f"{Fore.YELLOW}[!] mac-vendor-lookup not installed. Limited vendor detection.{Style.RESET_ALL}")

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print(f"{Fore.YELLOW}[!] python-nmap not installed. Limited port scanning.{Style.RESET_ALL}")

class NetworkScanner:
    def __init__(self, interface):
        self.interface = interface
        self.discovered_devices = []
        self.nm = nmap.PortScanner() if NMAP_AVAILABLE else None
        self.mac_lookup = MacLookup() if MAC_LOOKUP_AVAILABLE else None
        
        if MAC_LOOKUP_AVAILABLE:
            try:
                self.mac_lookup.load_vendors()
            except:
                print(f"{Fore.YELLOW}[!] MAC vendor database not loaded{Style.RESET_ALL}")
        
        self.device_signatures = {
            'smart_tv': {
                'ports': [1925, 1926, 7676, 8008, 8009, 9080, 50222, 52235],
                'manufacturers': [
                    'Sony', 'Samsung Electronics', 'LG Electronics', 'TCL', 'Vizio', 
                    'Philips', 'Sharp', 'Panasonic', 'Hisense'
                ],
                'hostnames': ['bravia', 'tv', 'smart-tv', 'samsung-tv', 'lg-tv', 'sony-tv']
            },
            'set_top_box': {
                'ports': [8080, 49152, 52235],
                'manufacturers': ['Airtel', 'Roku', 'Apple', 'Amazon'],
                'hostnames': ['settopbox', 'stb', 'roku', 'appletv', 'firetv']
            },
            'router': {
                'ports': [80, 443, 8080, 8443],
                'manufacturers': ['Cisco', 'Netgear', 'Asus', 'TP-Link', 'D-Link'],
                'hostnames': ['router', 'gateway', 'ap', 'access-point']
            }
        }

    def get_device_info(self, ip, mac):
        """Get detailed device information"""
        info = {
            'ip': ip,
            'mac': mac.upper(),
            'type': 'Unknown',
            'vendor': 'Unknown',
            'hostname': ip,
            'ports': [],
            'services': [],
            'last_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'status': 'online'
        }
        
        try:
            # Get vendor information
            if MAC_LOOKUP_AVAILABLE:
                try:
                    info['vendor'] = self.mac_lookup.lookup(mac)
                except:
                    mac_prefix = mac.replace(':', '').upper()[:6]
                    info['vendor'] = f"MAC Prefix: {mac_prefix}"

            # Get hostname
            try:
                info['hostname'] = socket.gethostbyaddr(ip)[0]
            except:
                pass

            # Port scanning
            if NMAP_AVAILABLE:
                try:
                    self.nm.scan(ip, arguments='-sS -F -n -T4')
                    if ip in self.nm.all_hosts():
                        for proto in self.nm[ip].all_protocols():
                            ports = self.nm[ip][proto].keys()
                            info['ports'].extend(list(ports))
                except:
                    # Fallback to basic port scanning
                    self._basic_port_scan(ip, info)

            # Device type detection based on ports and hostname
            if self.check_sony_tv(ip) or self.check_samsung_tv(ip):
                info['type'] = 'Smart TV'
            elif any(tv_port in info['ports'] for tv_port in [8008, 8009, 9080, 50222]):
                info['type'] = 'Smart TV'
            elif 'tv' in info['hostname'].lower():
                info['type'] = 'Smart TV'
            elif any(stb_port in info['ports'] for stb_port in [49152, 8080]):
                info['type'] = 'Set Top Box'
            elif any(name in info['hostname'].lower() for name in ['settop', 'stb']):
                info['type'] = 'Set Top Box'

        except Exception as e:
            print(f"{Fore.RED}[!] Error getting device info for {ip}: {str(e)}{Style.RESET_ALL}")

        return info

    def _basic_port_scan(self, ip, info):
        """Basic port scanning fallback"""
        common_ports = [80, 443, 8008, 8009, 9080, 1925, 1926, 7676, 50222, 52235]
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    info['ports'].append(port)
                sock.close()
            except:
                continue

    def _detect_device_type(self, info):
        """Enhanced device type detection"""
        # Add IoT device signatures
        iot_signatures = {
            'camera': {
                'ports': [80, 443, 554, 1935, 8000, 8080],
                'manufacturers': ['Hikvision', 'Dahua', 'Axis', 'Foscam'],
                'paths': ['/onvif/', '/axis-cgi/', '/webcam/']
            },
            'printer': {
                'ports': [631, 9100],
                'manufacturers': ['HP', 'Canon', 'Epson', 'Brother'],
                'paths': ['/printer/', '/ipp/', '/cups/']
            },
            'thermostat': {
                'ports': [80, 443, 8080],
                'manufacturers': ['Nest', 'Ecobee', 'Honeywell'],
                'paths': ['/tstat/', '/ecobee/']
            }
        }
        
        # Add signature detection
        for device_type, sigs in {**self.device_signatures, **iot_signatures}.items():
            if self._match_device_signature(info, sigs):
                info['type'] = device_type.replace('_', ' ').title()
                return

        # Add service fingerprinting
        if NMAP_AVAILABLE:
            self._fingerprint_services(info)

    def _fingerprint_services(self, info):
        """Enhanced service fingerprinting"""
        try:
            if self.nm:
                self.nm.scan(info['ip'], arguments='-sV -sC --version-intensity 5')
                if info['ip'] in self.nm.all_hosts():
                    for proto in self.nm[info['ip']].all_protocols():
                        ports = self.nm[info['ip']][proto].keys()
                        for port in ports:
                            service = self.nm[info['ip']][proto][port]
                            if 'product' in service:
                                info['services'].append({
                                    'port': port,
                                    'name': service.get('name', ''),
                                    'product': service.get('product', ''),
                                    'version': service.get('version', ''),
                                    'extrainfo': service.get('extrainfo', '')
                                })
        except Exception as e:
            print(f"{Fore.RED}[!] Service fingerprinting error: {str(e)}{Style.RESET_ALL}")

    def check_sony_tv(self, ip):
        """Check specifically for Sony TV"""
        try:
            # Try multiple Sony-specific endpoints
            endpoints = [
                (50222, '/sony/system'),
                (50222, '/sony/webapi/v1.0'),
                (80, '/sony/webapi'),
                (52323, '/sony')
            ]
            
            for port, path in endpoints:
                try:
                    response = requests.get(
                        f"http://{ip}:{port}{path}",
                        timeout=2,
                        headers={'X-Auth-PSK': 'sony'}
                    )
                    if response.status_code in [200, 403]:
                        return True
                except:
                    continue

            return False
        except:
            return False

    def check_samsung_tv(self, ip):
        """Check specifically for Samsung TV"""
        try:
            endpoints = [
                (8001, '/api/v2/'),
                (8002, '/ws/api'),
                (8080, '/ws/apps')
            ]
            
            for port, path in endpoints:
                try:
                    response = requests.get(f"http://{ip}:{port}{path}", timeout=2)
                    if response.status_code == 200:
                        return True
                except:
                    continue

            return False
        except:
            return False
    def arp_scan(self, ip_range=None):
        """Perform ARP scan and get device information"""
        if not ip_range:
            ip_range = self.get_network_range()
            
        print(f"{Fore.YELLOW}[*] Starting ARP scan on {self.interface} ({ip_range})...{Style.RESET_ALL}")
        
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        try:
            result = srp(packet, timeout=3, iface=self.interface, verbose=False)[0]
            
            # Clear previous results to avoid duplicates
            self.discovered_devices = []
            
            seen_ips = set()  # Track seen IPs to avoid duplicates
            
            for sent, received in result:
                if received.psrc not in seen_ips:
                    device_info = self.get_device_info(received.psrc, received.hwsrc)
                    self.discovered_devices.append(device_info)
                    seen_ips.add(received.psrc)
                    print(f"{Fore.GREEN}[+] Found device: {device_info['ip']} ({device_info['hostname']}) - {device_info['type']}{Style.RESET_ALL}")
                
        except Exception as e:
            print(f"{Fore.RED}[!] Error during ARP scan: {str(e)}{Style.RESET_ALL}")

        return self.discovered_devices

    def get_network_range(self):
        """Get the network range for the specified interface"""
        try:
            addrs = netifaces.ifaddresses(self.interface)
            if netifaces.AF_INET in addrs:
                ip_info = addrs[netifaces.AF_INET][0]
                if 'addr' in ip_info and 'netmask' in ip_info:
                    ip_parts = ip_info['addr'].split('.')
                    return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        except Exception as e:
            print(f"{Fore.RED}[!] Error getting network range: {str(e)}{Style.RESET_ALL}")
            return "192.168.1.0/24"  # fallback
