# Installation Guide

## System Requirements

### Minimum Requirements

- Python 3.8 or higher
- 4GB RAM
- Debian/Ubuntu or Kali Linux (recommended)
- Root/sudo privileges

### Required System Tools

- nmap
- tcpdump
- arp-scan
- python3-dev

## Installation Steps

### 1. System Dependencies

For Debian/Ubuntu-based systems:
bash
sudo apt update
sudo apt install -y python3-dev python3-pip python3-venv
sudo apt install -y nmap tcpdump arp-scan

### 2. Clone Repository

bash
git clone https://github.com/brighteyekid/Device-ghost.git
cd Device-ghost

### 3. Virtual Environment

bash
python3 -m venv venv
source venv/bin/activate # Linux/Mac

or
.\venv\Scripts\activate # Windows

### 4. Python Dependencies

pip install -r requirements.txt

### 5. Initial Setup

bash
python setup.py

## Troubleshooting

### Common Issues

1. **Permission Denied**

   - Run with sudo privileges
   - Check file permissions

2. **Missing Dependencies**

   - Ensure all system packages are installed
   - Update pip: `pip install --upgrade pip`

3. **Network Interface Issues**
   - Verify interface exists
   - Check interface permissions
