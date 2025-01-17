from flask import Flask, render_template, jsonify, request
from colorama import Fore, Style
from datetime import datetime
from recon.scanner import NetworkScanner
from exploit.exploit_handler import ExploitHandler
import sys
import netifaces

class WebInterface:
    def __init__(self, host="127.0.0.1", port=5000):
        self.app = Flask(__name__)
        self.host = host
        self.port = port
        self.scanner = None
        self.exploit_handler = ExploitHandler()
        self.devices = []
        self.interface = None
        self.setup_routes()

    def set_interface(self, interface):
        """Set network interface and initialize scanner"""
        try:
            # Verify interface exists
            if interface not in netifaces.interfaces():
                raise ValueError(f"Interface {interface} not found")

            self.interface = interface
            self.scanner = NetworkScanner(interface)
            print(f"{Fore.BLUE}[*] Scanner initialized for interface: {interface}{Style.RESET_ALL}")
            
            # Perform initial scan
            self.scan_network()
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error initializing scanner: {str(e)}{Style.RESET_ALL}")
            sys.exit(1)

    def scan_network(self):
        """Perform network scan"""
        try:
            if not self.scanner:
                raise Exception("Scanner not initialized")

            # Get network range
            network_range = self.scanner.get_network_range()
            if not network_range:
                raise Exception(f"Could not determine network range for interface {self.interface}")

            print(f"{Fore.YELLOW}[*] Starting scan on {self.interface} ({network_range}){Style.RESET_ALL}")
            
            # Perform scan
            self.devices = self.scanner.arp_scan(network_range)
            
            print(f"{Fore.GREEN}[+] Scan completed. Found {len(self.devices)} devices{Style.RESET_ALL}")
            return True

        except Exception as e:
            print(f"{Fore.RED}[!] Scan error: {str(e)}{Style.RESET_ALL}")
            return False

    def setup_routes(self):
        @self.app.route('/')
        def index():
            return render_template('index.html')

        @self.app.route('/api/devices')
        def get_devices():
            try:
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                devices_info = []
                
                for device in self.devices:
                    device_info = {
                        'name': device.get('hostname', 'Unknown'),
                        'ip': device.get('ip', 'Unknown'),
                        'mac': device.get('mac', 'Unknown'),
                        'type': device.get('type', 'Unknown'),
                        'vendor': device.get('vendor', 'Unknown'),
                        'ports': device.get('ports', []),
                        'last_seen': current_time,
                        'status': device.get('status', 'online'),
                        'services': device.get('services', [])
                    }
                    devices_info.append(device_info)
                
                return jsonify(devices_info)
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/scan', methods=['POST'])
        def start_scan():
            try:
                if self.scan_network():
                    return jsonify({
                        'status': 'success',
                        'message': f'Scan completed. Found {len(self.devices)} devices',
                        'devices_count': len(self.devices)
                    })
                else:
                    return jsonify({
                        'status': 'error',
                        'message': 'Scan failed'
                    }), 500
            except Exception as e:
                return jsonify({
                    'status': 'error',
                    'message': str(e)
                }), 500

        @self.app.route('/api/exploits/<device_type>')
        def get_exploits(device_type):
            try:
                exploits = self.exploit_handler.available_exploits.get(device_type.lower(), {})
                return jsonify(exploits)
            except Exception as e:
                return jsonify({
                    'status': 'error',
                    'message': str(e)
                }), 500

        @self.app.route('/api/exploit/run', methods=['POST'])
        def run_exploit():
            try:
                data = request.get_json()
                if not data:
                    return jsonify({'status': 'error', 'message': 'No data provided'}), 400

                exploit_id = data.get('exploit_id')
                device_ip = data.get('device_ip')
                device_type = data.get('device_type', 'unknown')

                if not exploit_id or not device_ip:
                    return jsonify({
                        'status': 'error',
                        'message': 'Missing required parameters'
                    }), 400

                result = self.exploit_handler.run_exploit(exploit_id, device_ip)
                return jsonify({
                    'status': 'success',
                    'message': result,
                    'exploit_id': exploit_id,
                    'target': device_ip
                })

            except Exception as e:
                return jsonify({
                    'status': 'error',
                    'message': str(e)
                }), 500

    def run(self):
        """Start the web interface"""
        try:
            print(f"{Fore.GREEN}[+] Starting web interface at http://{self.host}:{self.port}{Style.RESET_ALL}")
            self.app.run(host=self.host, port=self.port, debug=False)
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to start web interface: {str(e)}{Style.RESET_ALL}")
            sys.exit(1)

    def update_devices(self, devices):
        """Update the devices list with new scan results"""
        self.devices = devices
        print(f"{Fore.GREEN}[+] Updated device list with {len(devices)} devices{Style.RESET_ALL}")