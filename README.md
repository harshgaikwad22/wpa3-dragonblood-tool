# Automated WPA3-Transition Downgrade Attack Tool

## Overview

This project implements an automated security testing tool that demonstrates the Dragonblood vulnerability in WPA3 Wi-Fi networks. The tool specifically targets WPA3 networks, allowing for downgrade attacks that can compromise network security.

**Disclaimer**: This tool is for educational and authorized security testing purposes only. Unauthorized use against networks you don't own or have explicit permission to test is illegal.

## Features

- **Automated AP Discovery**: Uses airodump-ng to scan for nearby Wi-Fi networks
- **Vulnerability Detection**: Identifies WPA3-only and WPA3/2 transition mode access points
- **Security Analysis**: Extracts detailed security information including encryption ciphers, authentication methods, and MFP status
- **Interactive Target Selection**: Allows user to select specific APs for testing
- **Rogue AP Deployment**: Automatically configures and launches hostapd-mana for attack scenarios
- **Comprehensive Reporting**: Provides detailed information about detected vulnerabilities

## Tech Stack

- **Programming Language**: Python 3.x
- **Key Libraries**:
  - Scapy - Packet manipulation and analysis
  - Subprocess - System command execution
- **External Tools**:
  - airodump-ng (from Aircrack-ng suite)
  - hostapd-mana
  - iwconfig/ip utilities

## System Requirements

### Hardware

- Wireless network interfaces (2 required):
  - One supporting monitor mode (for scanning)
  - One supporting AP mode (for rogue AP)
  - High-power adapters

### Software

- **Operating System**: Kali Linux 2023.x or later (recommended)
- **Dependencies**:
  - Python 3.8+
  - Aircrack-ng suite
  - hostapd-mana
  - Scapy

## Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/harshgaikwad22/wpa3-dragonblood-tool.git
cd wpa3-dragonblood-tool
```

### 2. Install Dependencies

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install aircrack-ng hostapd-mana python3-pip -y

# Install Python dependencies
pip3 install scapy
```

### 3. Verify Interface Compatibility

```bash
# Check available wireless interfaces
iw dev

# Start monitor mode on one of the interfaces
sudo airmon-ng check kill
sudo airmon-ng start <interface>
```

## Usage

### Basic Usage

```bash
sudo python3 main.py -m <interface in monitor mode> -r <interface in managed mode>
```

### Parameters

- `-m, --monitor`: Monitor mode interface for scanning
- `-r, --rogue`: Interface for rogue AP deployment

### Execution Flow

1. **Discovery Phase** (60 seconds):

   - The tool scans for nearby Wi-Fi networks
   - Captures beacon frames and probe responses
   - Analyzes security configurations

2. **Analysis Phase**:

   - Identifies WPA3-capable networks
   - Classifies as WPA3-only or transition mode
   - Displays vulnerable targets

3. **Selection Phase**:

   - User selects target APs interactively
   - Shows detailed security information

4. **Attack Phase**:
   - Configures rogue AP with target settings
   - Launches hostapd-mana instance
   - Monitors for client associations and reassociations

### Example Output

```
Found 3 target AP(s). Please select which ones to attack:
----------------------------------------------------------------------------------------------------
[WPA3-Only APs]
[1] WPA3-Only | SSID: CorporateSecure       | BSSID: AA:BB:CC:DD:EE:FF | Channel: 36

[WPA3/2 Transition APs - VULNERABLE TO DRAGONBLOOD]
[2] Transition | SSID: HomeNetwork          | BSSID: 11:22:33:44:55:66 | Channel: 6
[3] Transition | SSID: GuestWiFi            | BSSID: 99:88:77:66:55:44 | Channel: 149

----------------------------------------------------------------------------------------------------

[?] Enter your selection (e.g., 1,3,5): 2
```

## Project Structure

```
wpa3-dragonblood-tool/
├── main.py                 # Main entry point and interface management
├── new_attack_flow.py      # Core attack orchestration logic
├── airodump_utils.py       # Wireless scanning and packet capture
├── extract_security_info.py # Security information extraction
├── extract_vulnerable_aps.py # Vulnerability detection and analysis
├── setup_rogue_ap.py       # Rogue AP configuration and deployment
└── README.md
```

### Key Components

- **main.py**: Handles command-line arguments and interface mode management
- **new_attack_flow.py**: Orchestrates the complete attack workflow
- **airodump_utils.py**: Manages wireless scanning using airodump-ng
- **extract_security_info.py**: Parses 802.11 security elements (RSN, WPA)
- **extract_vulnerable_aps.py**: Identifies Dragonblood-vulnerable networks
- **setup_rogue_ap.py**: Configures and launches rogue access points

## Demo Video

[Link to demonstration video showing the tool in action]

## Final Presentation

[Link to final project presentation slides]

## Contributors

- **Harshwardhan Gaikwad**
- **Suyash Chaudhary**
- **Devagya Yadav**

## Legal and Ethical Notice

This tool is designed for:

- Security researchers testing their own networks
- Penetration testers with proper authorization
- Educational purposes in controlled environments

**Important**: Always ensure you have explicit written permission before testing any network you don't own. Unauthorized network access is illegal and unethical.

## References

- [Dragonblood: A Security Analysis of WPA3's SAE](https://papers.mathyvanhoef.com/dragonblood.pdf)
- [Wi-Fi Alliance WPA3 Specification](https://www.wi-fi.org/discover-wi-fi/security)
- [hostapd-mana Documentation](https://github.com/sensepost/hostapd-mana)
- [Dragonshift](https://github.com/jabbaw0nky/DragonShift)

```

```
