#!/usr/bin/env python3
"""
Network Traffic Analyzer
Captures and analyzes live network traffic, detecting:
- Port scans
- ARP spoofing
- Brute force / repeated connections

# To run: sudo python3 traffic_analyzer.py -i <interface>
# Example: sudo python3 traffic_analyzer.py -i eth0
# Find your interface with: ip a
"""

from scapy.all import sniff, ARP, TCP, IP, ICMP
from collections import defaultdict
import argparse
import time

# ─── Thresholds ────────────────────────────────────────────────────────────────
PORT_SCAN_THRESHOLD = 10       # unique ports from one IP in time window
BRUTE_FORCE_THRESHOLD = 10     # repeated connections to same port in time window
TIME_WINDOW = 5                # seconds to track activity

# ─── State tracking ───────────────────────────────────────────────────────────
port_scan_tracker = defaultdict(lambda: {"ports": set(), "last_seen": 0})
brute_force_tracker = defaultdict(lambda: {"count": 0, "last_seen": 0})
arp_table = {}  # ip -> mac

# ─── Colors ───────────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
RESET  = "\033[0m"

def alert(level, msg):
    color = RED if level == "HIGH" else YELLOW
    print(f"{color}[!] [{level}] {msg}{RESET}")

def info(msg):
    print(f"{CYAN}[*] {msg}{RESET}")

# ─── Detection functions ───────────────────────────────────────────────────────
def detect_port_scan(src_ip, dst_port):
    now = time.time()
    tracker = port_scan_tracker[src_ip]

    if now - tracker["last_seen"] > TIME_WINDOW:
        tracker["ports"] = set()

    tracker["ports"].add(dst_port)
    tracker["last_seen"] = now

    if len(tracker["ports"]) >= PORT_SCAN_THRESHOLD:
        alert("HIGH", f"Port scan detected from {src_ip} — {len(tracker['ports'])} ports scanned")
        tracker["ports"] = set()  # reset after alert

def detect_brute_force(src_ip, dst_ip, dst_port):
    now = time.time()
    key = (src_ip, dst_ip, dst_port)
    tracker = brute_force_tracker[key]

    if now - tracker["last_seen"] > TIME_WINDOW:
        tracker["count"] = 0

    tracker["count"] += 1
    tracker["last_seen"] = now

    if tracker["count"] >= BRUTE_FORCE_THRESHOLD:
        alert("HIGH", f"Brute force detected: {src_ip} → {dst_ip}:{dst_port} ({tracker['count']} attempts)")
        tracker["count"] = 0  # reset after alert

def detect_arp_spoof(pkt):
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP reply
        src_ip = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc

        if src_ip in arp_table:
            if arp_table[src_ip] != src_mac:
                alert("HIGH", f"ARP spoofing detected! {src_ip} changed MAC: {arp_table[src_ip]} → {src_mac}")
        else:
            arp_table[src_ip] = src_mac

# ─── Packet handler ───────────────────────────────────────────────────────────
def handle_packet(pkt):
    # ARP spoofing
    if pkt.haslayer(ARP):
        detect_arp_spoof(pkt)

    # TCP analysis
    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        src_ip  = pkt[IP].src
        dst_ip  = pkt[IP].dst
        dst_port = pkt[TCP].dport
        flags   = pkt[TCP].flags

        # Log SYN packets (connection attempts)
        if flags == "S":
            info(f"TCP SYN: {src_ip} → {dst_ip}:{dst_port}")
            detect_port_scan(src_ip, dst_port)
            detect_brute_force(src_ip, dst_ip, dst_port)

        # Log RST packets (rejected connections)
        elif flags == "R":
            info(f"TCP RST: {src_ip} → {dst_ip}:{dst_port} (connection rejected)")

    # ICMP analysis
    if pkt.haslayer(ICMP) and pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        icmp_type = pkt[ICMP].type
        if icmp_type == 8:
            info(f"ICMP Ping: {src_ip} → {dst_ip}")

# ─── CLI ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Network Traffic Analyzer — Detects port scans, ARP spoofing, and brute force attacks",
        epilog="""
Examples:
  sudo python3 traffic_analyzer.py -i eth0
  sudo python3 traffic_analyzer.py -i wlan0
  sudo python3 traffic_analyzer.py -i eth0 -c 100

Find your interface with: ip a
        """
    )
    parser.add_argument("-i", "--interface", required=True, help="Network interface to sniff on (e.g. eth0, wlan0)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    args = parser.parse_args()

    print("=" * 55)
    print("        Network Traffic Analyzer")
    print("=" * 55)
    print(f"  Interface : {args.interface}")
    print(f"  Packets   : {'Unlimited' if args.count == 0 else args.count}")
    print(f"  Detecting : Port scans, ARP spoofing, Brute force")
    print("=" * 55)
    print(f"{GREEN}[+] Starting capture... Press Ctrl+C to stop{RESET}\n")

    try:
        sniff(iface=args.interface, prn=handle_packet, count=args.count, store=False)
    except KeyboardInterrupt:
        print(f"\n{GREEN}[+] Capture stopped.{RESET}")
    except PermissionError:
        print(f"{RED}[!] Permission denied. Run with sudo.{RESET}")

if __name__ == "__main__":
    main()