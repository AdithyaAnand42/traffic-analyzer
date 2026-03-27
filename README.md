# Network Traffic Analyzer

A real-time network packet capture and analysis tool built in Python using Scapy. Monitors live network traffic and automatically detects suspicious activity.

## Features
- Real-time packet capture on any network interface
- Detects port scans (10+ ports from a single IP)
- Detects ARP spoofing attacks
- Detects brute force / repeated connection attempts
- Color-coded alerts (HIGH severity in red)
- Logs all TCP SYN, RST, and ICMP ping packets

## Usage
```
sudo python3 traffic_analyzer.py -i <interface>
```

## Examples
```
# Monitor on WiFi
sudo python3 traffic_analyzer.py -i wlan0

# Monitor on ethernet
sudo python3 traffic_analyzer.py -i eth0

# Capture only 100 packets
sudo python3 traffic_analyzer.py -i wlan0 -c 100
```

## Requirements
```
pip install scapy
```

## Demo
Successfully detected live port scan attacks in real time during testing against local network infrastructure.

## Disclaimer
For educational purposes only. Only use on networks you own or have permission to monitor.
