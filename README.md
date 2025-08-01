# Simple Network Packet Analyzer

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://www.python.org/)
[![Scapy Version](https://img.shields.io/badge/scapy-2.4.5%2B-blue.svg)](https://scapy.net/)

A lightweight network packet analyzer using Scapy to capture and inspect IP, TCP, and UDP traffic in real-time. Displays source/destination information and payload samples.

## Features
- Real-time packet capture and analysis
- Protocol identification (TCP/UDP/Other)
- Source/destination IP and port display
- Payload preview (first 50 bytes)
- Interface selection and packet count limitation
- Simple command-line interface

## Prerequisites
- Python 3.6+
- Scapy (`pip install scapy`)
- Root/Administrator privileges
- You must have Npcap installed (in WinPcap compatibility mode) and run your script as Administrator.

## Installation
```bash
git clone https://github.com/yourusername/network-packet-analyzer.git
cd network-packet-analyzer
