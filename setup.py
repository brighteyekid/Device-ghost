#!/usr/bin/env python3
import os
import sys
from colorama import init, Fore, Style

def check_directories():
    dirs = [
        'src/recon',
        'src/exploit',
        'src/mitm',
        'src/payload',
        'src/web/static/css',
        'src/web/static/js',
        'src/web/templates',
        'src/utils',
        'logs',
        'captures',
        'data'
    ]
    
    # Create __init__.py files for Python packages
    for dir_path in dirs:
        full_path = os.path.join(os.path.dirname(__file__), dir_path)
        if not os.path.exists(full_path):
            print(f"{Fore.YELLOW}[*] Creating directory: {dir_path}{Style.RESET_ALL}")
            os.makedirs(full_path)
            # Create __init__.py if it's a Python package directory
            if 'src/' in dir_path:
                init_file = os.path.join(full_path, '__init__.py')
                if not os.path.exists(init_file):
                    open(init_file, 'a').close()

def check_dependencies():
    try:
        import flask
        import scapy
        import nmap
        import netifaces
    except ImportError as e:
        print(f"{Fore.RED}[!] Missing dependency: {str(e)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Please run: pip install -r requirements.txt{Style.RESET_ALL}")
        return False
    return True

def check_system_dependencies():
    """Check for required system tools"""
    tools = ['nmap', 'tcpdump', 'arp-scan']
    missing_tools = []
    
    for tool in tools:
        if os.system(f'which {tool} > /dev/null 2>&1') != 0:
            missing_tools.append(tool)
    
    if missing_tools:
        print(f"{Fore.RED}[!] Missing system tools: {', '.join(missing_tools)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Please install them using your package manager{Style.RESET_ALL}")
        return False
    return True

def main():
    init()
    print(f"{Fore.GREEN}[+] Setting up DeviceGhost environment...{Style.RESET_ALL}")
    
    check_directories()
    if not check_dependencies() or not check_system_dependencies():
        sys.exit(1)
    
    # Create example config file if it doesn't exist
    config_file = os.path.join(os.path.dirname(__file__), 'config.example.ini')
    if not os.path.exists(config_file):
        with open(config_file, 'w') as f:
            f.write("""[General]
interface = eth0
web_host = 127.0.0.1
web_port = 5000

[Logging]
level = INFO
file = logs/deviceghost.log

[Scanner]
timeout = 5
aggressive = false
""")
    
    print(f"{Fore.GREEN}[+] Setup complete!{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] You can now run: sudo -E python3 src/main.py -i <interface> -m <mode> [-w]{Style.RESET_ALL}")

if __name__ == "__main__":
    main() 