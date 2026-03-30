from scapy.all import *
from datetime import datetime

packet_count = 0

def packet_callback(packet):
    global packet_count
    packet_count += 1

    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        protocol = "OTHER"

        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        log = f"{datetime.now()} | {src} -> {dst} | {protocol}"
        print(log)

        # Save to file
        with open("log.txt", "a") as file:
            file.write(log + "\n")

# Start sniffing
print("Starting Packet Sniffer...")
sniff(filter="ip", prn=packet_callback, count=50)

print(f"\nTotal Packets Captured: {packet_count}")
