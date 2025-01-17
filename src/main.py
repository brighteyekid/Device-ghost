#!/usr/bin/env python3

import argparse
import sys
import os
from colorama import init, Fore, Style

# Add virtual environment path to system path
venv_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'venv/lib/python3.12/site-packages')
sys.path.append(venv_path)

try:
    from recon.scanner import NetworkScanner
    from exploit.exploit_handler import ExploitHandler
    from mitm.mitm_handler import MITMHandler
    from payload.payload_generator import PayloadGenerator
    from web.web_interface import WebInterface
except ImportError as e:
    print(f"{Fore.RED}[!] Error importing required modules: {str(e)}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Make sure all dependencies are installed:{Style.RESET_ALL}")
    print("    pip install python-nmap scapy netifaces colorama flask")
    print(f"{Fore.YELLOW}[*] Current Python path:{Style.RESET_ALL}")
    for path in sys.path:
        print(f"    {path}")
    sys.exit(1)

def print_banner():
    print(f"""{Fore.CYAN}
    ██████╗ ███████╗██╗   ██╗██╗ ██████╗███████╗ ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
    ██╔══██╗██╔════╝██║   ██║██║██╔════╝██╔════╝██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
    ██║  ██║█████╗  ██║   ██║██║██║     █████╗  ██║  ███╗███████║██║   ██║███████╗   ██║   
    ██║  ██║██╔══╝  ╚██╗ ██╔╝██║██║     ██╔══╝  ██║   ██║██╔══██║██║   ██║╚════██║   ██║   
    ██████╔╝███████╗ ╚████╔╝ ██║╚██████╗███████╗╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   
    ╚═════╝ ╚══════╝  ╚═══╝  ╚═╝ ╚═════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   
    {Style.RESET_ALL}
    {Fore.RED}[*] Networked Device Exploitation Framework{Style.RESET_ALL}
    """)

def check_root():
    if sys.platform.startswith('linux') and os.geteuid() != 0:
        print(f"{Fore.RED}[!] This script must be run as root!{Style.RESET_ALL}")
        sys.exit(1)

def check_interface(interface):
    try:
        import netifaces
        if interface not in netifaces.interfaces():
            print(f"{Fore.RED}[!] Interface {interface} not found!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Available interfaces: {', '.join(netifaces.interfaces())}{Style.RESET_ALL}")
            sys.exit(1)
    except ImportError:
        print(f"{Fore.YELLOW}[!] netifaces not installed, skipping interface verification{Style.RESET_ALL}")

def parse_arguments():
    parser = argparse.ArgumentParser(description='DeviceGhost - Network Device Exploitation Framework')
    parser.add_argument('-i', '--interface', required=True, help='Network interface to use')
    parser.add_argument('-m', '--mode', choices=['recon', 'exploit'], default='recon', help='Operation mode')
    parser.add_argument('-w', '--web', action='store_true', help='Start web interface')
    parser.add_argument('-r', '--range', help='IP range to scan (e.g., 192.168.1.0/24)')
    return parser.parse_args()

def main():
    init()  # Initialize colorama
    print_banner()
    
    # Check if running as root
    check_root()
    
    # Parse arguments
    args = parse_arguments()
    
    # Check interface
    check_interface(args.interface)

    print(f"{Fore.GREEN}[+] Starting DeviceGhost...{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Using interface: {args.interface}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Mode: {args.mode}{Style.RESET_ALL}")

    try:
        if args.web:
            web_interface = WebInterface()
            web_interface.set_interface(args.interface)
            web_interface.run()
        else:
            # Handle CLI-only mode
            scanner = NetworkScanner(args.interface)
            
            # Use provided IP range or auto-detect
            ip_range = args.range if args.range else scanner.get_network_range()
            if not ip_range:
                raise Exception("Could not determine network range. Please specify using -r option.")
                
            print(f"{Fore.YELLOW}[*] Scanning network range: {ip_range}{Style.RESET_ALL}")
            devices = scanner.arp_scan(ip_range)
            
            # Print results
            print(f"\n{Fore.GREEN}[+] Discovered Devices:{Style.RESET_ALL}")
            for device in devices:
                print(f"\n{Fore.CYAN}Device:{Style.RESET_ALL}")
                print(f"  IP: {device['ip']}")
                print(f"  MAC: {device['mac']}")
                print(f"  Type: {device['type']}")
                print(f"  Vendor: {device['vendor']}")
                if device.get('ports'):
                    print(f"  Open Ports: {', '.join(map(str, device['ports']))}")
                print(f"  Hostname: {device.get('hostname', 'Unknown')}")
                print(f"  Status: {device.get('status', 'Unknown')}")

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] An error occurred: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main() 