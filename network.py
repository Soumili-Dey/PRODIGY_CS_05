from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
import argparse
import platform

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        
        protocol = {6: "TCP", 17: "UDP"}.get(proto, str(proto))
        
        print(f"IP Packet: {ip_src} -> {ip_dst} | Protocol: {protocol}")
        
        if packet.haslayer(TCP):
            print(f"  TCP: Sport={packet[TCP].sport} -> Dport={packet[TCP].dport}")
            if packet[TCP].payload:
                payload = bytes(packet[TCP].payload)
                print(f"  Payload: {payload[:50].hex()}")  # Show hexdump for Windows compatibility
        
        elif packet.haslayer(UDP):
            print(f"  UDP: Sport={packet[UDP].sport} -> Dport={packet[UDP].dport}")
            if packet[UDP].payload:
                payload = bytes(packet[UDP].payload)
                print(f"  Payload: {payload[:50].hex()}")

def list_interfaces():
    """List all available network interfaces"""
    print("\nAvailable interfaces:")
    for idx, iface in enumerate(get_windows_if_list()):
        print(f"{idx + 1}. {iface['name']} ({iface['description']})")
    print()

def main():
    parser = argparse.ArgumentParser(description="Windows Network Packet Analyzer")
    parser.add_argument("-i", "--interface", type=int, help="Interface index to sniff on (use -l to list)")
    parser.add_argument("-c", "--count", type=int, help="Number of packets to capture", default=0)
    parser.add_argument("-l", "--list", action="store_true", help="List available interfaces")
    args = parser.parse_args()
    
    if args.list:
        list_interfaces()
        return
        
    if args.interface:
        ifaces = get_windows_if_list()
        try:
            iface_name = ifaces[args.interface - 1]['name']
        except IndexError:
            print(f"\nError: Invalid interface index. Use -l to list available interfaces.")
            return
    else:
        iface_name = None  # Use default interface
        
    print("Starting packet sniffer... Press Ctrl+C to stop.")
    print("------------------------------------------------")
    
    try:
        # Windows-specific sniffing parameters
        sniff(
            iface=iface_name,
            prn=packet_callback,
            count=args.count,
            store=0  # Important for Windows performance
        )
    except KeyboardInterrupt:
        print("\nSniffer stopped by user.")
    except PermissionError:
        print("\nError: Permission denied. Run as Administrator!")
    except Exception as e:
        print(f"\nError: {e}")

if __name__ == "__main__":
    # Check OS compatibility
    if platform.system() != 'Windows':
        print("\nError: This script is optimized for Windows. Use Linux version for other systems.")
    else:
        main()