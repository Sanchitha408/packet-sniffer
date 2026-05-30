#!/usr/bin/env python3
"""
Packet Sniffer — captures and displays live network packets.
Filters by protocol: TCP, UDP, ICMP, or ALL.
Run as root on Kali Linux.
"""

import socket
import struct
import argparse
import textwrap
from datetime import datetime


# ── Colour codes for terminal output ──────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GREY   = "\033[90m"

PROTO_COLOUR = {
    "TCP":  GREEN,
    "UDP":  CYAN,
    "ICMP": YELLOW,
    "OTHER": GREY,
}

# Protocol number → name
PROTO_MAP = {6: "TCP", 17: "UDP", 1: "ICMP"}


# ── Parsers ────────────────────────────────────────────────────────────────────

def parse_ethernet(raw):
    """Returns (dest_mac, src_mac, eth_proto, payload)."""
    dest, src, proto = struct.unpack("! 6s 6s H", raw[:14])
    return (
        format_mac(dest),
        format_mac(src),
        socket.ntohs(proto),
        raw[14:],
    )


def parse_ipv4(raw):
    """Returns (version, ttl, proto_num, src_ip, dest_ip, payload)."""
    version_ihl = raw[0]
    ihl = (version_ihl & 0xF) * 4          # header length in bytes
    ttl, proto_num = raw[8], raw[9]
    src  = socket.inet_ntoa(raw[12:16])
    dest = socket.inet_ntoa(raw[16:20])
    return version_ihl >> 4, ttl, proto_num, src, dest, raw[ihl:]


def parse_tcp(raw):
    """Returns (src_port, dest_port, seq, ack, flags_str)."""
    src_port, dest_port, seq, ack, offset_flags = struct.unpack("! H H L L H", raw[:14])
    offset = (offset_flags >> 12) * 4
    flags  = offset_flags & 0x1FF
    flag_str = _tcp_flags(flags)
    return src_port, dest_port, seq, ack, flag_str, raw[offset:]


def parse_udp(raw):
    """Returns (src_port, dest_port, length, payload)."""
    src_port, dest_port, length = struct.unpack("! H H H", raw[:6])
    return src_port, dest_port, length, raw[8:]


def parse_icmp(raw):
    """Returns (icmp_type, code, checksum)."""
    icmp_type, code, checksum = struct.unpack("! B B H", raw[:4])
    return icmp_type, code, checksum


# ── Helpers ────────────────────────────────────────────────────────────────────

def format_mac(raw_bytes):
    return ":".join(f"{b:02x}" for b in raw_bytes)


def _tcp_flags(flags):
    names = ["FIN","SYN","RST","PSH","ACK","URG","ECE","CWR","NS"]
    bits  = [0x001,0x002,0x004,0x008,0x010,0x020,0x040,0x080,0x100]
    return "|".join(n for n, b in zip(names, bits) if flags & b) or "NONE"


def timestamp():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]
def print_separator():
    print(GREY + "─" * 72 + RESET)


# ── Display ────────────────────────────────────────────────────────────────────

def display_packet(proto_name, src_ip, dest_ip, extra_fields, pkt_num):
    colour = PROTO_COLOUR.get(proto_name, GREY)
    print_separator()
    print(f"{BOLD}#{pkt_num:<4}{RESET}  {colour}{BOLD}{proto_name:<6}{RESET}  "
          f"{GREY}{timestamp()}{RESET}")
    print(f"  {BOLD}SRC{RESET}  {src_ip:<20}  "
          f"{BOLD}DEST{RESET}  {dest_ip}")
    for label, value in extra_fields:
        print(f"  {GREY}{label:<14}{RESET}{value}")


# ── Core sniff loop ────────────────────────────────────────────────────────────

def sniff(filter_proto, count):
    """
    Opens a raw socket and processes packets.
    filter_proto : "ALL" | "TCP" | "UDP" | "ICMP"
    count        : max packets to capture (0 = unlimited)
    """
    try:
        # AF_PACKET captures all traffic at Ethernet level (Linux only)
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except PermissionError:
        print(f"{RED}[!] Root privileges required. Run: sudo python3 sniffer.py{RESET}")
        return
    except OSError as e:
        print(f"{RED}[!] Socket error: {e}{RESET}")
        return

    print(f"\n{BOLD}Packet Sniffer{RESET}  |  filter={BOLD}{filter_proto}{RESET}  "
          f"|  count={'unlimited' if count == 0 else count}")
    print(f"Press {BOLD}Ctrl+C{RESET} to stop.\n")

    pkt_num   = 0
    captured  = 0

    try:
        while True:
            raw_data, _ = conn.recvfrom(65536)
            pkt_num += 1

            # ── Ethernet ──────────────────────────────────────────────────────
            dest_mac, src_mac, eth_proto, ip_payload = parse_ethernet(raw_data)

            # Only process IPv4 (0x0800)
            if eth_proto != 8:
                continue

            # ── IPv4 ──────────────────────────────────────────────────────────
            ver, ttl, proto_num, src_ip, dest_ip, transport = parse_ipv4(ip_payload)
            proto_name = PROTO_MAP.get(proto_num, "OTHER")

            # Apply filter
            if filter_proto != "ALL" and proto_name != filter_proto:
                continue

            # ── Protocol-specific parsing ─────────────────────────────────────
            if proto_name == "TCP":
                try:
                    sp, dp, seq, ack, flags, _ = parse_tcp(transport)
                    extras = [
                        ("Sport → Dport", f"{sp} → {dp}"),
                        ("Flags",         flags),
                        ("Seq / Ack",     f"{seq} / {ack}"),
                        ("TTL",           ttl),
                    ]
                except Exception:
                    extras = [("TTL", ttl)]

            elif proto_name == "UDP":
                try:
                    sp, dp, length, _ = parse_udp(transport)
                    extras = [
                        ("Sport → Dport", f"{sp} → {dp}"),
                        ("Length",        length),
                        ("TTL",           ttl),
                    ]
                except Exception:
                    extras = [("TTL", ttl)]

            elif proto_name == "ICMP":
                try:
                    icmp_type, code, checksum = parse_icmp(transport)
                    extras = [
                        ("Type / Code",   f"{icmp_type} / {code}"),
                        ("Checksum",      hex(checksum)),
                        ("TTL",           ttl),
                    ]
                except Exception:
                    extras = [("TTL", ttl)]

            else:
                extras = [("Proto num", proto_num), ("TTL", ttl)]

            display_packet(proto_name, src_ip, dest_ip, extras, pkt_num)
            captured += 1

            if count and captured >= count:
                print(f"\n{GREEN}[+] Captured {captured} packets. Done.{RESET}\n")
                break

    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}[*] Stopped. Total captured: {captured}{RESET}\n")
    finally:
        conn.close()


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Packet Sniffer — captures live network traffic",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              sudo python3 sniffer.py                   # capture all protocols
              sudo python3 sniffer.py -p TCP            # TCP only
              sudo python3 sniffer.py -p UDP -c 20      # 20 UDP packets then stop
              sudo python3 sniffer.py -p ICMP           # ICMP only (ping traffic)
        """),
    )
    parser.add_argument(
        "-p", "--protocol",
        choices=["ALL", "TCP", "UDP", "ICMP"],
        default="ALL",
        help="Protocol filter (default: ALL)",
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Stop after N packets (default: 0 = unlimited)",
    )
    args = parser.parse_args()
    sniff(args.protocol.upper(), args.count)


if __name__ == "__main__":
    main()
