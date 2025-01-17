
# **DeviceGhost 🌐**  

<p align="center">  
  <img src="logo/deviceghost.png" alt="DeviceGhost Logo" width="200"/>  
</p>  

**DeviceGhost** is a powerful IoT device security testing framework designed for network security professionals and researchers. This framework provides comprehensive reconnaissance, exploitation, and man-in-the-middle (MITM) capabilities for testing IoT devices, smart TVs, routers, and other networked devices.  

---

## **🔑 Key Features**  

- **Device Discovery & Fingerprinting**  
  - Automated network scanning  
  - Device type detection  
  - Service enumeration  
  - Vulnerability assessment  

- **Exploitation Modules**  
  - Smart TV exploits (Samsung, LG, Sony)  
  - Camera exploits (Hikvision, Dahua)  
  - Router exploits (MikroTik, TP-Link, Netgear)  
  - Default credential testing  
  - Firmware manipulation  

- **MITM Capabilities**  
  - ARP spoofing  
  - DNS spoofing  
  - SSL stripping  
  - Packet capture  
  - Traffic analysis  

- **Web Interface**  
  - Real-time device monitoring  
  - Exploit management  
  - Network visualization  
  - Attack logging  

---

## **🛡️ Supported Devices**  

- **Smart TVs**  
  - Samsung Smart TV  
  - LG WebOS TV  
  - Sony Bravia  
  - Roku TV  

- **Network Cameras**  
  - Hikvision  
  - Dahua  
  - Axis  
  - Foscam  

- **Routers**  
  - MikroTik  
  - TP-Link  
  - D-Link  
  - Netgear  

- **IoT Devices**  
  - Smart Home Devices  
  - Set-top Boxes  
  - Streaming Devices  
  - Network Printers  

---

## **🚀 Quick Start**  

### **Prerequisites**  
- Python 3.8+  
- Nmap  
- tcpdump  
- arp-scan  

### **Installation**  

1. **Clone the repository**:  
   ```bash  
   git clone https://github.com/brighteyekid/Device-ghost.git  
   cd Device-ghost  
   ```  

2. **Set up a virtual environment**:  
   ```bash  
   python3 -m venv venv  
   source venv/bin/activate  # Linux/Mac  
   # or for Windows  
   .\venv\Scripts\activate  
   ```  

3. **Install dependencies**:  
   ```bash  
   pip install -r requirements.txt  
   ```  

4. **Run the setup script**:  
   ```bash  
   python setup.py  
   ```  

5. **Start DeviceGhost**:  
   ```bash  
   sudo python3 src/main.py -i eth0 -m recon   # Reconnaissance mode  
   sudo python3 src/main.py -i eth0 -w        # Launch web interface  
   sudo python3 src/main.py -i eth0 -r 192.168.1.0/24  # Network scan  
   ```  

---

## **📁 Project Structure**  

```plaintext  
Device-ghost/  
├── src/  
│   ├── recon/        # Reconnaissance modules  
│   ├── exploit/      # Exploit modules  
│   ├── mitm/         # MITM attack modules  
│   ├── payload/      # Payload generators  
│   └── web/          # Web interface  
├── docs/             # Documentation  
├── tests/            # Test cases  
└── tools/            # Additional tools  
```  

---

## **⚠️ Disclaimer**  

DeviceGhost is intended for **educational and authorized testing purposes only**. Users are responsible for complying with applicable laws and regulations. The authors are not responsible for any misuse or damage caused by this program.  

---

## **📝 License**  

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.  

---

## **📚 Documentation**  

Detailed documentation is available in the [docs](docs/) directory:  
- [Installation Guide](docs/installation.md)  
- [Usage Guide](docs/usage.md)  

---

## **🤝 Acknowledgments**  

- Thanks to all contributors  
- Inspired by various open-source security tools  
- Built with Python and ❤️  

---

## **📧 Contact**  

- **Project Link**: [DeviceGhost Repository](https://github.com/brighteyekid/Device-ghost)  
- **Report Bugs**: [Issue Tracker](https://github.com/brighteyekid/Device-ghost/issues)  

---

### Made with ❤️ by [brighteyekid](https://github.com/brighteyekid)  
