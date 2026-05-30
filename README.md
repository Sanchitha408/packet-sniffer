# Packet Sniffer

A command-line network packet sniffer built in Python using raw sockets.  
Captures live traffic and displays **source IP, destination IP, protocol, and port** for every packet — with optional protocol filtering.

> **Platform:** Linux (Kali Linux recommended)  
> **Requires:** Python 3.6+ · Root privileges

---

## Features

- Captures TCP, UDP, and ICMP packets in real time
- Displays source IP, destination IP, ports, flags, TTL, and checksum
- Filter by protocol via a single flag (`-p TCP / UDP / ICMP / ALL`)
- Stop automatically after N packets (`-c 50`)
- Colour-coded terminal output — green for TCP, cyan for UDP, yellow for ICMP
- No external libraries — uses Python's built-in `socket` and `struct`

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/packet-sniffer.git
cd packet-sniffer
```

### 2. (Optional) Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Run the sniffer

```bash
# Capture all protocols
sudo python3 sniffer.py

# TCP packets only
sudo python3 sniffer.py -p TCP

# UDP packets only
sudo python3 sniffer.py -p UDP

# ICMP only — open another terminal and run: ping google.com
sudo python3 sniffer.py -p ICMP

# Capture exactly 20 packets then stop
sudo python3 sniffer.py -p TCP -c 20
```

---

## Sample Output

```
Packet Sniffer  |  filter=TCP  |  count=unlimited
Press Ctrl+C to stop.

────────────────────────────────────────────────────────────────────────
#1    TCP     14:32:05.412
  SRC  192.168.1.5           DEST  142.250.77.46
  Sport → Dport  54321 → 443
  Flags         SYN
  Seq / Ack     3201847291 / 0
  TTL           64

────────────────────────────────────────────────────────────────────────
#2    TCP     14:32:05.413
  SRC  142.250.77.46         DEST  192.168.1.5
  Sport → Dport  443 → 54321
  Flags         SYN|ACK
  Seq / Ack     892734612 / 3201847292
  TTL           117
```

---

## How It Works

The sniffer opens a raw `AF_PACKET` socket which receives **all Ethernet frames** on the interface before the OS network stack processes them. Each frame is manually parsed:

```
Ethernet frame
└── IPv4 header  (source IP, dest IP, protocol number, TTL)
    ├── TCP segment   (ports, sequence numbers, flags)
    ├── UDP datagram  (ports, length)
    └── ICMP message  (type, code, checksum)
```

Parsing is done using Python's `struct.unpack` — no external libraries required. This means you can read exactly how each protocol header is laid out in memory, which is useful context for understanding network-level attacks like SYN floods, spoofing, and ICMP-based recon.

---

## Testing It

**Test TCP:** Open a browser or run `curl https://example.com` in another terminal.

**Test UDP:** Run `dig google.com` — DNS uses UDP on port 53.

**Test ICMP:** Run `ping 8.8.8.8` — each ping sends an ICMP Echo Request.

---

## Requirements

- Linux OS (uses `AF_PACKET` — not available on Windows/macOS)
- Python 3.6+
- Root / sudo privileges (raw sockets require elevated permissions)
- No pip packages needed

---

## Project Structure

```
packet-sniffer/
├── sniffer.py       # Main script
└── README.md        # This file
```

---

## Skills Demonstrated

- Raw socket programming in Python
- Manual binary protocol parsing with `struct`
- TCP/IP model (Ethernet → IPv4 → TCP/UDP/ICMP)
- Linux networking internals
- CLI design with `argparse`

---

## Author

**Sanchitha** — [GitHub: Sanchitha408](https://github.com/Sanchitha408)  
1st year CSE student | Cybersecurity enthusiast | TryHackMe practitioner
