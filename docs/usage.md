# Usage Guide

## Basic Usage

### Command Line Interface

1. Basic Network Scan

bash
sudo python3 src/main.py -i eth0 -m recon

2. With Web Interface

sudo python3 src/main.py -i eth0 -w

3. Specify IP Range
   bash
   sudo python3 src/main.py -i eth0 -r 192.168.1.0/24

### Command Line Arguments

| Argument        | Description                    | Example           |
| --------------- | ------------------------------ | ----------------- |
| -i, --interface | Network interface to use       | -i eth0           |
| -m, --mode      | Operation mode (recon/exploit) | -m recon          |
| -w, --web       | Start web interface            | -w                |
| -r, --range     | IP range to scan               | -r 192.168.1.0/24 |

## Features

### 1. Reconnaissance

#### Network Scanning

bash

# Basic network scan

sudo python3 src/main.py -i eth0 -m recon

# Advanced scan with custom range

sudo python3 src/main.py -i eth0 -m recon -r 192.168.1.0/24

#### Device Detection

- Automatic device type detection
- Service fingerprinting
- Vulnerability assessment

### 2. Exploitation

#### Smart TV Exploits

bash

# Example: Samsung TV exploit

sudo python3 src/main.py -i eth0 -m exploit --target 192.168.1.100 --exploit samsung_remote

#### Camera Exploits

bash

# Example: Hikvision exploit

sudo python3 src/main.py -i eth0 -m exploit --target 192.168.1.101 --exploit hikvision_bypass

### 3. MITM Attacks

#### ARP Spoofing

bash

# Start ARP spoofing

sudo python3 src/main.py -i eth0 --mitm arp --target 192.168.1.100

#### Packet Capture

bash

# Capture packets

sudo python3 src/main.py -i eth0 --capture --target 192.168.1.100

## Web Interface

### Accessing the Interface

1. Start with web interface enabled:

bash
sudo python3 src/main.py -i eth0 -w

2. Open browser and navigate to: `http://127.0.0.1:5000`

### Features

- Real-time device monitoring
- Exploit management
- Network visualization
- Attack logging

## Best Practices

1. **Before Starting**

   - Verify network permissions
   - Check target scope
   - Review local regulations

2. **During Operation**

   - Monitor system resources
   - Log all activities
   - Regular status checks

3. **After Usage**
   - Clean up temporary files
   - Review logs
   - Document findings

## Safety Considerations

1. **Legal Compliance**

   - Only test authorized systems
   - Maintain proper documentation
   - Follow local regulations

2. **Network Safety**

   - Use isolated test environments
   - Monitor network stability
   - Have rollback procedures

3. **Data Protection**
   - Secure captured data
   - Remove sensitive information
   - Use encryption when necessary
