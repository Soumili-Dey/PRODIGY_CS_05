from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
import argparse

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        
        protocol = ""
        if proto == 6:
            protocol = "TCP"
        elif proto == 17:
            protocol = "UDP"
        else:
            protocol = str(proto)
        
        print(f"IP Packet: {ip_src} -> {ip_dst} | Protocol: {protocol}")
        
        if packet.haslayer(TCP):
            print(f"TCP: Sport={packet[TCP].sport} -> Dport={packet[TCP].dport}")
            if len(packet[TCP].payload) > 0:
                payload = bytes(packet[TCP].payload)
                print(f"Payload: {payload[:50]}...")  # Show first 50 bytes
        
        elif packet.haslayer(UDP):
            print(f"UDP: Sport={packet[UDP].sport} -> Dport={packet[UDP].dport}")
            if len(packet[UDP].payload) > 0:
                payload = bytes(packet[UDP].payload)
                print(f"Payload: {payload[:50]}...")

def main():
    parser = argparse.ArgumentParser(description="Simple Network Packet Analyzer")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on", default=None)
    parser.add_argument("-c", "--count", help="Number of packets to capture", type=int, default=0)
    args = parser.parse_args()
    
    print("Starting packet sniffer... Press Ctrl+C to stop.")
    print("-----------------------------------------------")
    
    try:
        if args.interface:
            sniff(iface=args.interface, prn=packet_callback, count=args.count)
        else:
            sniff(prn=packet_callback, count=args.count)
    except KeyboardInterrupt:
        print("\nSniffer stopped by user.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()