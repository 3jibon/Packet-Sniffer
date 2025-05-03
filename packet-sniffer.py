#!/usr/bin/env python3

from scapy.all import *
import argparse
import sys
from pyfiglet import figlet_format
from scapy.layers.inet import IP, TCP
from scapy.layers.dns import DNS, DNSQR


def print_banner():
    banner = figlet_format("Packet Sniffer", font="slant")
    print(banner)
    print("Developed by Farhan Uddin Jibon\n")

def capture_http(packet):
    """Capture and analyze HTTP packets for sensitive data."""
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        try:
            payload = packet[Raw].load
            if b'HTTP' in payload:
                sensitive_fields = [b'password', b'login', b'username', 
                                   b'credit_card', b'cc_number', b'ssn']
                if any(field in payload.lower() for field in sensitive_fields):
                    print("\n[!] Potential sensitive data in HTTP packet:")
                    print(f"Source: {packet[IP].src}:{packet[TCP].sport}")
                    print(f"Destination: {packet[IP].dst}:{packet[TCP].dport}")
                    try:
                        print("Payload:", payload.decode('utf-8', errors='replace'))
                    except UnicodeDecodeError:
                        print("Payload: (binary data)")
                    print("-" * 50)
        except Exception as e:
            print(f"[HTTP Processing Error] {str(e)}")

def capture_dns(packet):
    """Capture and log DNS queries."""
    if packet.haslayer(DNS) and packet[DNS].qr == 0:  # DNS query (not response)
        try:
            query = packet[DNSQR].qname.decode('utf-8', errors='replace')
            print(f"[DNS] Query: {query} from {packet[IP].src}")

            # Check for suspicious domains
            suspicious_keywords = ['malware', 'phish', 'exploit', 'attack']
            if any(keyword in query.lower() for keyword in suspicious_keywords):
                print(f"[!] Suspicious DNS query detected: {query}")
        except Exception as e:
            print(f"[DNS Processing Error] {str(e)}")

def start_sniffing(interface):
    """Start packet capture on specified interface."""
    print(f"\n[*] Starting packet capture on {interface} (Press CTRL+C to stop)...")
    print("[*] Monitoring HTTP and DNS traffic...\n")

    try:
        sniff(iface=interface,
              filter="tcp port 80 or udp port 53",
              prn=process_packet,
              store=0)
    except PermissionError:
        print("\n[!] Error: Permission denied. Try running with sudo.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        sys.exit(1)

def process_packet(packet):
    """Process incoming packets and route to appropriate handlers."""
    if packet.haslayer(DNS):
        capture_dns(packet)
    elif packet.haslayer(TCP) and packet.haslayer(Raw):
        capture_http(packet)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Simple Network Packet Sniffer - Captures HTTP and DNS traffic",
        epilog="Example: sudo python3 packet_sniffer.py -i eth0"
    )
    parser.add_argument("-i", "--interface",
                        help="Network interface to sniff on",
                        required=True)

    args = parser.parse_args()

    print_banner()

    try:
        start_sniffing(args.interface)
    except KeyboardInterrupt:
        print("\n[*] Stopping packet capture...")
