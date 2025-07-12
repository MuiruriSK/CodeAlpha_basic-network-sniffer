# Basic Network Sniffer

A Python-based network packet capture and analysis tool designed to help you understand network traffic, protocols, and data flow.

## Features

- **Real-time packet capture** using the Scapy library
- **Protocol analysis** (TCP, UDP, ICMP, ARP, DNS, HTTP/HTTPS)
- **Color-coded output** for easy protocol identification
- **Comprehensive statistics** including protocol distribution, top IPs, and ports
- **Payload analysis** with both text and hex representation
- **Flexible filtering** using BPF (Berkeley Packet Filter) syntax
- **Cross-platform support** (Windows, Linux, macOS)

## Installation

### Prerequisites

- Python 3.7 or higher
- Administrator/root privileges (required for packet capture)

### Setup

1. **Clone or download this project**
2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

### Windows Users

On Windows, you may need to install additional components:

1. **Install Npcap** (required for packet capture):
   - Download from: https://npcap.com/
   - Install with default settings

2. **Run as Administrator**:
   - Right-click on Command Prompt or PowerShell
   - Select "Run as administrator"
   - Navigate to your project directory

## Usage

### Basic Usage

```bash
# Capture all packets (requires Ctrl+C to stop)
python network_sniffer.py

# List available network interfaces
python network_sniffer.py --list-interfaces

# Capture on specific interface
python network_sniffer.py -i "Ethernet"

# Capture only HTTP traffic (port 80)
python network_sniffer.py -f "tcp port 80"

# Capture only 100 packets
python network_sniffer.py -c 100

# Combine options
python network_sniffer.py -i "Wi-Fi" -f "udp" -c 50
```

### Command Line Options

- `-i, --interface`: Specify network interface to capture on
- `-f, --filter`: BPF filter string (e.g., "tcp port 443")
- `-c, --count`: Number of packets to capture
- `--list-interfaces`: Show available network interfaces

### Filter Examples

```bash
# HTTP traffic
python network_sniffer.py -f "tcp port 80"

# HTTPS traffic
python network_sniffer.py -f "tcp port 443"

# DNS queries
python network_sniffer.py -f "udp port 53"

# Specific IP address
python network_sniffer.py -f "host 192.168.1.1"

# Traffic between two hosts
python network_sniffer.py -f "host 192.168.1.1 and host 8.8.8.8"

# Exclude local traffic
python network_sniffer.py -f "not src net 192.168.0.0/16"
```

## Understanding Network Protocols

### TCP (Transmission Control Protocol)
- **Purpose**: Reliable, ordered data delivery
- **Common ports**: 80 (HTTP), 443 (HTTPS), 22 (SSH), 21 (FTP)
- **Characteristics**: Connection-oriented, error checking, flow control

### UDP (User Datagram Protocol)
- **Purpose**: Fast, lightweight data transmission
- **Common ports**: 53 (DNS), 67/68 (DHCP), 123 (NTP), 161 (SNMP)
- **Characteristics**: Connectionless, no error checking, no flow control

### ICMP (Internet Control Message Protocol)
- **Purpose**: Network diagnostics and error reporting
- **Common uses**: Ping, traceroute, error messages
- **Characteristics**: Built into IP, used for network troubleshooting

### ARP (Address Resolution Protocol)
- **Purpose**: Maps IP addresses to MAC addresses
- **Usage**: Local network communication
- **Characteristics**: Layer 2 protocol, local network only

### DNS (Domain Name System)
- **Purpose**: Translates domain names to IP addresses
- **Port**: 53 (UDP for queries, TCP for zone transfers)
- **Characteristics**: Hierarchical, distributed database

## Packet Structure Analysis

### IP Header
```
Version (4 bits) | IHL (4 bits) | Type of Service (8 bits) | Total Length (16 bits)
Identification (16 bits) | Flags (3 bits) | Fragment Offset (13 bits)
Time to Live (8 bits) | Protocol (8 bits) | Header Checksum (16 bits)
Source IP Address (32 bits)
Destination IP Address (32 bits)
```

### TCP Header
```
Source Port (16 bits) | Destination Port (16 bits)
Sequence Number (32 bits)
Acknowledgment Number (32 bits)
Data Offset (4 bits) | Reserved (6 bits) | Flags (6 bits) | Window Size (16 bits)
Checksum (16 bits) | Urgent Pointer (16 bits)
Options (variable)
```

### UDP Header
```
Source Port (16 bits) | Destination Port (16 bits)
Length (16 bits) | Checksum (16 bits)
Data (variable)
```

## Educational Value

This tool helps you learn:

1. **Network Fundamentals**: How data flows through networks
2. **Protocol Behavior**: Differences between TCP, UDP, and other protocols
3. **Packet Analysis**: Understanding packet headers and payloads
4. **Network Troubleshooting**: Identifying network issues and anomalies
5. **Security Awareness**: Understanding what data is transmitted over networks

## Sample Output

```
[+] Starting packet capture...
[+] Press Ctrl+C to stop capture
============================================================
[14:23:45.123] Protocol: TCP | Length: 66 bytes | Source: 192.168.1.100:52431 | Destination: 8.8.8.8:443
    Payload: GET / HTTP/1.1\r\nHost: www.google.com\r\n...
[14:23:45.145] Protocol: UDP | Length: 74 bytes | Source: 192.168.1.100:52432 | Destination: 8.8.8.8:53
    Payload: 4854 0100 0001 0000 0000 0000 0377 7777...
[14:23:45.167] Protocol: ICMP | Length: 84 bytes | Source: 192.168.1.100 | Destination: 8.8.8.8
    Payload: No payload

============================================================
CAPTURE STATISTICS
============================================================

Protocol Distribution:
+----------+-------+
| Protocol | Count |
+----------+-------+
| TCP      |    45 |
| UDP      |    23 |
| ICMP     |     8 |
| DNS      |    12 |
+----------+-------+

Top IP Addresses:
+-------------+-------+
| IP Address  | Count |
+-------------+-------+
| 8.8.8.8     |    35 |
| 192.168.1.1 |    28 |
| 1.1.1.1     |    15 |
+-------------+-------+

Total packets captured: 88
```

## Troubleshooting

### Common Issues

1. **Permission Denied**:
   - Run as administrator/root
   - On Windows, ensure Npcap is installed

2. **No Packets Captured**:
   - Check if interface name is correct
   - Verify network connectivity
   - Try without interface specification

3. **Import Errors**:
   - Install dependencies: `pip install -r requirements.txt`
   - Ensure Python 3.7+ is installed

### Windows-Specific Issues

1. **Npcap Installation**:
   - Download from https://npcap.com/
   - Install with "Install Npcap in WinPcap API-compatible Mode"

2. **Firewall/Antivirus**:
   - Temporarily disable to test
   - Add exceptions for the Python executable

## Security and Legal Considerations

⚠️ **Important**: This tool is for educational purposes only.

- **Legal Use**: Only capture traffic on networks you own or have explicit permission to monitor
- **Privacy**: Be aware that packet capture can reveal sensitive information
- **Compliance**: Ensure compliance with local laws and regulations
- **Ethical Use**: Respect privacy and use responsibly

## Contributing

Feel free to enhance this tool with additional features:
- Packet filtering improvements
- More protocol support
- GUI interface
- Packet export functionality
- Advanced analysis features

## License

This project is for educational purposes. Use responsibly and in accordance with applicable laws and regulations. 