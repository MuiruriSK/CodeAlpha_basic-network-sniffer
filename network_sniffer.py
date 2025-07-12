#!/usr/bin/env python3
# type: ignore
"""
Basic Network Sniffer
A Python program to capture and analyze network traffic packets.
"""

import sys
import time
import argparse
from datetime import datetime
from collections import defaultdict
import signal
import os

try:
    import scapy.all as scapy
    from colorama import init, Fore, Back, Style
    from tabulate import tabulate
except ImportError as e:
    print(f"Error: Missing required library. Please install dependencies: {e}")
    print("Run: pip install -r requirements.txt")
    sys.exit(1)

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class NetworkSniffer:
    def __init__(self):
        self.packet_count = 0
        self.protocol_stats = defaultdict(int)
        self.ip_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        self.captured_packets = []
        self.running = False
        
    def signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        print(f"\n{Fore.YELLOW}[!] Stopping packet capture...")
        self.running = False
        
    def get_protocol_name(self, packet):
        """Extract protocol name from packet"""
        if packet.haslayer(scapy.TCP):  # type: ignore
            return "TCP"
        elif packet.haslayer(scapy.UDP):  # type: ignore
            return "UDP"
        elif packet.haslayer(scapy.ICMP):  # type: ignore
            return "ICMP"
        elif packet.haslayer(scapy.ARP):  # type: ignore
            return "ARP"
        elif packet.haslayer(scapy.DNS):  # type: ignore
            return "DNS"
        elif packet.haslayer(scapy.DHCP):  # type: ignore
            return "DHCP"
        elif packet.haslayer(scapy.BOOTP):  # type: ignore
            return "BOOTP"
        elif packet.haslayer(scapy.TFTP):  # type: ignore
            return "TFTP"
        elif packet.haslayer(scapy.SNMP):  # type: ignore
            return "SNMP"
        elif packet.haslayer(scapy.NTP):  # type: ignore
            return "NTP"
        elif packet.haslayer(scapy.SMTP):  # type: ignore
            return "SMTP"
        elif packet.haslayer(scapy.POP):  # type: ignore
            return "POP"
        elif packet.haslayer(scapy.IMAP):  # type: ignore
            return "IMAP"
        elif packet.haslayer(scapy.FTP):  # type: ignore
            return "FTP"
        elif packet.haslayer(scapy.SSH):  # type: ignore
            return "SSH"
        elif packet.haslayer(scapy.TELNET):  # type: ignore
            return "TELNET"
        elif packet.haslayer(scapy.HTTP):  # type: ignore
            return "HTTP"
        elif packet.haslayer(scapy.HTTPS):  # type: ignore
            return "HTTPS"
        elif packet.haslayer(scapy.RIP):  # type: ignore
            return "RIP"
        elif packet.haslayer(scapy.OSPF):  # type: ignore
            return "OSPF"
        elif packet.haslayer(scapy.BGP):  # type: ignore
            return "BGP"
        elif packet.haslayer(scapy.IGMP):  # type: ignore
            return "IGMP"
        elif packet.haslayer(scapy.EIGRP):  # type: ignore
            return "EIGRP"
        elif packet.haslayer(scapy.VRRP):  # type: ignore
            return "VRRP"
        elif packet.haslayer(scapy.HSRP):  # type: ignore
            return "HSRP"
        elif packet.haslayer(scapy.STP):  # type: ignore
            return "STP"
        elif packet.haslayer(scapy.CDP):  # type: ignore
            return "CDP"
        elif packet.haslayer(scapy.LLDP):  # type: ignore
            return "LLDP"
        elif packet.haslayer(scapy.ISAKMP):  # type: ignore
            return "ISAKMP"
        elif packet.haslayer(scapy.IKE):  # type: ignore
            return "IKE"
        elif packet.haslayer(scapy.ESP):  # type: ignore
            return "ESP"
        elif packet.haslayer(scapy.AH):  # type: ignore
            return "AH"
        elif packet.haslayer(scapy.GRE):  # type: ignore
            return "GRE"
        elif packet.haslayer(scapy.PPP):  # type: ignore
            return "PPP"
        elif packet.haslayer(scapy.PPPoE):  # type: ignore
            return "PPPoE"
        elif packet.haslayer(scapy.RADIUS):  # type: ignore
            return "RADIUS"
        elif packet.haslayer(scapy.TACACS):  # type: ignore
            return "TACACS"
        elif packet.haslayer(scapy.LDAP):  # type: ignore
            return "LDAP"
        elif packet.haslayer(scapy.KERBEROS):  # type: ignore
            return "KERBEROS"
        elif packet.haslayer(scapy.NFS):  # type: ignore
            return "NFS"
        elif packet.haslayer(scapy.SMB):  # type: ignore
            return "SMB"
        elif packet.haslayer(scapy.NETBIOS):  # type: ignore
            return "NETBIOS"
        elif packet.haslayer(scapy.SYSLOG):  # type: ignore
            return "SYSLOG"
        elif packet.haslayer(scapy.SNMP):  # type: ignore
            return "SNMP"
        elif packet.haslayer(scapy.DHCPv6):  # type: ignore
            return "DHCPv6"
        elif packet.haslayer(scapy.ICMPv6):  # type: ignore
            return "ICMPv6"
        elif packet.haslayer(scapy.NDP):  # type: ignore
            return "NDP"
        else:
            return "Other"
    
    def get_payload_info(self, packet):
        """Extract payload information from packet"""
        if packet.haslayer(scapy.Raw):  # type: ignore
            payload = packet[scapy.Raw].load  # type: ignore
            # Try to decode as string, fallback to hex
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
                if payload_str.isprintable():
                    return payload_str[:100] + "..." if len(payload_str) > 100 else payload_str
                else:
                    return payload.hex()[:50] + "..."
            except:
                return payload.hex()[:50] + "..."
        return "No payload"
    
    def analyze_packet(self, packet):
        """Analyze a single packet and extract useful information"""
        # Check if packet is valid
        if packet is None:
            return {
                'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                'length': 0,
                'protocol': 'Unknown',
                'src_ip': 'Unknown',
                'dst_ip': 'Unknown',
                'src_port': 'N/A',
                'dst_port': 'N/A',
                'payload': 'No payload'
            }
        
        packet_info = {
            'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
            'length': len(packet) if packet else 0,
            'protocol': 'Unknown',
            'src_ip': 'Unknown',
            'dst_ip': 'Unknown',
            'src_port': 'N/A',
            'dst_port': 'N/A',
            'payload': 'No payload'
        }
        
        try:
            # Extract IP information
            if packet.haslayer(scapy.IP):  # type: ignore
                packet_info['src_ip'] = packet[scapy.IP].src  # type: ignore
                packet_info['dst_ip'] = packet[scapy.IP].dst  # type: ignore
                self.ip_stats[packet[scapy.IP].src] += 1  # type: ignore
                self.ip_stats[packet[scapy.IP].dst] += 1  # type: ignore
            
            # Extract protocol information
            protocol = self.get_protocol_name(packet)
            packet_info['protocol'] = protocol
            self.protocol_stats[protocol] += 1
            
            # Extract port information
            if packet.haslayer(scapy.TCP):  # type: ignore
                packet_info['src_port'] = packet[scapy.TCP].sport  # type: ignore
                packet_info['dst_port'] = packet[scapy.TCP].dport  # type: ignore
                self.port_stats[f"{packet[scapy.TCP].sport}"] += 1  # type: ignore
                self.port_stats[f"{packet[scapy.TCP].dport}"] += 1  # type: ignore
            elif packet.haslayer(scapy.UDP):  # type: ignore
                packet_info['src_port'] = packet[scapy.UDP].sport  # type: ignore
                packet_info['dst_port'] = packet[scapy.UDP].dport  # type: ignore
                self.port_stats[f"{packet[scapy.UDP].sport}"] += 1  # type: ignore
                self.port_stats[f"{packet[scapy.UDP].dport}"] += 1  # type: ignore
            
            # Extract payload
            packet_info['payload'] = self.get_payload_info(packet)
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error analyzing packet: {e}")
            # Return basic packet info even if analysis fails
            packet_info['length'] = len(packet) if packet else 0
        
        return packet_info
    
    def packet_callback(self, packet):
        """Callback function called for each captured packet"""
        if not self.running:
            return
        
        try:
            self.packet_count += 1
            packet_info = self.analyze_packet(packet)
            self.captured_packets.append(packet_info)
            
            # Display packet information
            self.display_packet(packet_info)
            
            # Keep only last 100 packets in memory
            if len(self.captured_packets) > 100:
                self.captured_packets.pop(0)
        except Exception as e:
            print(f"{Fore.RED}[!] Error processing packet: {e}")
            # Continue processing other packets
    
    def display_packet(self, packet_info):
        """Display formatted packet information"""
        # Color coding based on protocol
        protocol_colors = {
            'TCP': Fore.BLUE,
            'UDP': Fore.GREEN,
            'ICMP': Fore.YELLOW,
            'ARP': Fore.MAGENTA,
            'DNS': Fore.CYAN,
            'DHCP': Fore.CYAN,
            'HTTP': Fore.RED,
            'HTTPS': Fore.RED,
            'FTP': Fore.RED,
            'SSH': Fore.RED,
            'SMTP': Fore.RED,
            'POP': Fore.RED,
            'IMAP': Fore.RED,
            'TELNET': Fore.RED,
            'SNMP': Fore.YELLOW,
            'NTP': Fore.YELLOW,
            'TFTP': Fore.YELLOW,
            'RIP': Fore.MAGENTA,
            'OSPF': Fore.MAGENTA,
            'BGP': Fore.MAGENTA,
            'IGMP': Fore.MAGENTA,
            'EIGRP': Fore.MAGENTA,
            'VRRP': Fore.MAGENTA,
            'HSRP': Fore.MAGENTA,
            'STP': Fore.MAGENTA,
            'CDP': Fore.MAGENTA,
            'LLDP': Fore.MAGENTA,
            'ISAKMP': Fore.RED,
            'IKE': Fore.RED,
            'ESP': Fore.RED,
            'AH': Fore.RED,
            'GRE': Fore.MAGENTA,
            'PPP': Fore.MAGENTA,
            'PPPoE': Fore.MAGENTA,
            'RADIUS': Fore.YELLOW,
            'TACACS': Fore.YELLOW,
            'LDAP': Fore.YELLOW,
            'KERBEROS': Fore.RED,
            'NFS': Fore.YELLOW,
            'SMB': Fore.YELLOW,
            'NETBIOS': Fore.YELLOW,
            'SYSLOG': Fore.YELLOW,
            'DHCPv6': Fore.CYAN,
            'ICMPv6': Fore.YELLOW,
            'NDP': Fore.CYAN,
            'Other': Fore.WHITE
        }
        
        color = protocol_colors.get(packet_info['protocol'], Fore.WHITE)
        
        print(f"{color}[{packet_info['timestamp']}] "
              f"Protocol: {packet_info['protocol']} | "
              f"Length: {packet_info['length']} bytes | "
              f"Source: {packet_info['src_ip']}:{packet_info['src_port']} | "
              f"Destination: {packet_info['dst_ip']}:{packet_info['dst_port']}")
        
        if packet_info['payload'] != "No payload":
            print(f"{Style.DIM}    Payload: {packet_info['payload']}")
    
    def display_statistics(self):
        """Display capture statistics"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}CAPTURE STATISTICS")
        print(f"{Fore.CYAN}{'='*60}")
        
        # Protocol statistics
        if self.protocol_stats:
            print(f"\n{Fore.YELLOW}Protocol Distribution:")
            protocol_data = [[protocol, count] for protocol, count in self.protocol_stats.items()]
            print(tabulate(protocol_data, headers=['Protocol', 'Count'], tablefmt='grid'))
        
        # Top IP addresses
        if self.ip_stats:
            print(f"\n{Fore.YELLOW}Top IP Addresses:")
            top_ips = sorted(self.ip_stats.items(), key=lambda x: x[1] if x[1] is not None else 0, reverse=True)[:10]
            ip_data = [[ip, count] for ip, count in top_ips]
            print(tabulate(ip_data, headers=['IP Address', 'Count'], tablefmt='grid'))
        
        # Top ports
        if self.port_stats:
            print(f"\n{Fore.YELLOW}Top Ports:")
            top_ports = sorted(self.port_stats.items(), key=lambda x: x[1] if x[1] is not None else 0, reverse=True)[:10]
            port_data = [[port, count] for port, count in top_ports]
            print(tabulate(port_data, headers=['Port', 'Count'], tablefmt='grid'))
        
        print(f"\n{Fore.GREEN}Total packets captured: {self.packet_count}")
    
    def start_capture(self, interface=None, filter_string=None, count=None, timeout=None):
        """Start packet capture"""
        self.running = True
        
        # Set up signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        
        print(f"{Fore.GREEN}[+] Starting packet capture...")
        if interface:
            print(f"{Fore.GREEN}[+] Interface: {interface}")
        if filter_string:
            print(f"{Fore.GREEN}[+] Filter: {filter_string}")
        if count:
            print(f"{Fore.GREEN}[+] Packet count limit: {count}")
        if timeout:
            print(f"{Fore.GREEN}[+] Timeout: {timeout} seconds")
        print(f"{Fore.GREEN}[+] Press Ctrl+C to stop capture")
        print(f"{Fore.CYAN}{'='*60}")
        
        try:
            # Start sniffing
            scapy.sniff(  # type: ignore
                iface=interface,
                filter=filter_string,
                prn=self.packet_callback,
                count=count,
                timeout=timeout,
                store=0  # Don't store packets in memory (we handle storage ourselves)
            )
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"{Fore.RED}[!] Error during capture: {e}")
            # Continue to display statistics even if there was an error
        finally:
            self.running = False
            try:
                self.display_statistics()
            except Exception as e:
                print(f"{Fore.RED}[!] Error displaying statistics: {e}")
                print(f"{Fore.GREEN}Total packets captured: {self.packet_count}")

def main():
    parser = argparse.ArgumentParser(
        description="Basic Network Sniffer - Capture and analyze network packets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python network_sniffer.py                    # Capture all packets
  python network_sniffer.py -i eth0            # Capture on specific interface
  python network_sniffer.py -f "tcp port 80"   # Capture only HTTP traffic
  python network_sniffer.py -c 100             # Capture only 100 packets
  python network_sniffer.py -i eth0 -f "udp"   # Capture UDP on eth0
        """
    )
    
    parser.add_argument('-i', '--interface', 
                       help='Network interface to capture on (default: auto-detect)')
    parser.add_argument('-f', '--filter', 
                       help='BPF filter string (e.g., "tcp port 80")')
    parser.add_argument('-c', '--count', type=int, 
                       help='Number of packets to capture (default: unlimited)')
    parser.add_argument('-t', '--timeout', type=int, 
                       help='Timeout in seconds (default: unlimited)')
    parser.add_argument('--list-interfaces', action='store_true',
                       help='List available network interfaces')
    
    args = parser.parse_args()
    
    # List interfaces if requested
    if args.list_interfaces:
        print(f"{Fore.CYAN}Available network interfaces:")
        interfaces = scapy.get_if_list()  # type: ignore
        for i, iface in enumerate(interfaces, 1):
            print(f"  {i}. {iface}")
        return
    
    # Validate filter if provided
    if args.filter:
        try:
            # Test if the filter is valid by trying to compile it
            # We'll use a simple validation approach
            if not any(keyword in args.filter.lower() for keyword in ['tcp', 'udp', 'icmp', 'arp', 'host', 'port', 'src', 'dst', 'net', 'and', 'or', 'not']):
                raise ValueError("Filter contains no valid BPF keywords")
        except Exception as e:
            print(f"{Fore.RED}[!] Invalid filter: {args.filter}")
            print(f"{Fore.RED}[!] Error: {e}")
            print(f"{Fore.YELLOW}[!] Valid filter examples:")
            print(f"{Fore.YELLOW}    tcp port 80")
            print(f"{Fore.YELLOW}    udp port 53")
            print(f"{Fore.YELLOW}    host 192.168.1.1")
            print(f"{Fore.YELLOW}    src host 192.168.1.1")
            print(f"{Fore.YELLOW}    tcp and port 443")
            return
    
    # Create and start sniffer
    sniffer = NetworkSniffer()
    sniffer.start_capture(
        interface=args.interface,
        filter_string=args.filter,
        count=args.count,
        timeout=args.timeout
    )

if __name__ == "__main__":
    # Check if running with administrator privileges (required for packet capture)
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print(f"{Fore.RED}[!] Warning: This program may require administrator privileges on Windows")
        except:
            pass
    else:  # Unix-like systems
        if os.geteuid() != 0:
            print(f"{Fore.RED}[!] Warning: This program may require root privileges")
    
    main() 