```markdown
# Packet Sniffer – Educational Network Traffic Monitor

A lightweight, passive packet sniffer written in Python using the `scapy` library.  
It captures **HTTP requests** (TCP port 80) and **DNS queries/responses** (UDP port 53) and logs them in a structured CSV file for security research, protocol analysis, and educational labs.

> ⚠️ **ETHICAL USE ONLY**  
> This tool is intended solely for **educational and research purposes on networks you own or have explicit written permission to monitor**.  
> Unauthorized interception of network traffic may violate local laws and is strictly prohibited.

---

## Features

- Auto-detects the default network interface (or accepts a command-line argument).
- Filters traffic live with a BPF expression: `tcp port 80 or udp port 53`.
- Extracts and displays:
  - **Timestamp** (UTC, ISO‑8601)
  - **Source / destination IP addresses and ports**
  - **HTTP method and URL** (for HTTP requests)
  - **DNS queried domain name** (QNAME)
- Prints human-readable output to the terminal and appends a CSV log (`packet_log.csv`).
- Gracefully handles permissions errors and Scapy exceptions.
- Fully typed with docstrings and a `__main__` guard for safe importing.

---

## Requirements

- **Python 3.7+**
- **scapy** ≥ 2.4.0
- Root / Administrator privileges (for raw socket access)

All Python dependencies are listed in [`requirements.txt`](requirements.txt).

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/packet-sniffer.git
   cd packet-sniffer
   ```

2. (Optional) Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate   # Linux/macOS
   ```

3. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage

Run the sniffer with `sudo` (root privileges required). By default it uses the system’s primary interface:

```bash
sudo python3 packet_sniffer.py
```

To specify a different interface (e.g., `eth0`, `en0`, `wlan0`):

```bash
sudo python3 packet_sniffer.py -i eth0
```

Stop the capture gracefully by pressing `Ctrl+C`.

### Example output

```
[*] Starting capture on interface 'en0' with filter 'tcp port 80 or udp port 53'
[*] Press Ctrl+C to stop.

2026-06-11T12:34:56.123456+00:00 | 192.168.1.10:52341 -> 93.184.216.34:80 [TCP] | HTTP GET /index.html
2026-06-11T12:34:57.654321+00:00 | 192.168.1.10:54321 -> 8.8.8.8:53 [UDP] | DNS query: example.com
```

---

## Log File Format

All captured packets are appended to `packet_log.csv` with the following columns:

| Column      | Description                               |
|-------------|-------------------------------------------|
| timestamp   | UTC time in ISO‑8601 format               |
| src_ip      | Source IPv4 address                       |
| dst_ip      | Destination IPv4 address                  |
| protocol    | `TCP` or `UDP`                            |
| src_port    | Source transport port                     |
| dst_port    | Destination transport port                |
| http_method | HTTP method (e.g., GET, POST) or empty     |
| http_url    | Requested URL path or empty               |
| dns_query   | DNS queried domain name or empty          |

The file is created automatically and includes a header on the first run.

---

## File Structure

```
.
├── packet_sniffer.py   # Main script
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

---

## Ethical & Legal Warning

**Unauthorised packet capture is illegal in many jurisdictions.**  
You **must** have explicit permission from the network owner before running this tool.  
It is provided **exclusively** for educational use, security training, network troubleshooting, and authorised penetration testing.

By using this software you agree that you understand and comply with all applicable laws and regulations. The author assumes **no liability** for misuse.

---

## License

This project is released under the [MIT License](LICENSE) – see the `LICENSE` file for details (you can add one if desired).
```

# Packet Sniffer – Enhanced Network Traffic Monitor

A significantly upgraded passive packet sniffer written in Python using `scapy`.

> ⚠️ **ETHICAL USE ONLY**  
> For **educational and research purposes only**, on networks you own or have explicit written permission to monitor.  
> Unauthorized interception of network traffic may violate local laws.

---

## What's New vs. Original

| Feature | Original | Upgraded |
|---|---|---|
| HTTP capture | ✅ | ✅ |
| DNS capture | ✅ | ✅ |
| **HTTPS / TLS SNI detection** | ❌ | ✅ |
| **ICMP support** | ❌ | ✅ |
| **ARP support** | ❌ | ✅ |
| **Colorized terminal output** | ❌ | ✅ |
| **Live stats printer** | ❌ | ✅ |
| **JSON-lines log format** | ❌ | ✅ |
| **Rotating / structured log dir** | ❌ | ✅ |
| **Protocol selector (CLI)** | ❌ | ✅ |
| **Packet count limit (-c)** | ❌ | ✅ |
| **SIGTERM graceful shutdown** | ❌ | ✅ |
| **Final summary on exit** | ❌ | ✅ |
| Thread-safe writes | ❌ | ✅ |
| Verbose / quiet modes | ❌ | ✅ |
| HTTP Host header extraction | ❌ | ✅ |

---

## Features

- **Multi-protocol capture**: HTTP, HTTPS/TLS (SNI), DNS, ICMP, ARP
- **TLS SNI extraction** – identify HTTPS destinations without decrypting traffic
- **Colorized output** – protocol-coded colors in the terminal (disable with `--no-color`)
- **Live statistics** – optional periodic stats dump (packets/sec, top DNS domains, etc.)
- **Structured logging** – CSV + optional JSON-lines in a dedicated log directory
- **Rotating application log** – `logs/sniffer_app.log` with size-based rotation
- **Flexible BPF filtering** – choose protocols via `--protocols` or pass a raw BPF string
- **Packet count limit** – stop automatically after N packets (`-c`)
- **Graceful shutdown** – handles both Ctrl-C and SIGTERM cleanly

---

## Requirements

- Python 3.9+
- scapy ≥ 2.5.0
- Root / Administrator privileges

---

## Installation

```bash
git clone <repo-url>
cd sniffer-upgraded
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

---

## Usage

```bash
# Basic: HTTP + HTTPS + DNS on default interface
sudo python3 sniffer.py

# Capture all supported protocols
sudo python3 sniffer.py -p http https dns icmp arp

# Specific interface, quiet mode (log only, no terminal output)
sudo python3 sniffer.py -i eth0 -q

# Stop after 500 packets, print live stats every 10s, also write JSON log
sudo python3 sniffer.py -c 500 --stats-interval 10 --json

# Custom BPF filter
sudo python3 sniffer.py -f "tcp port 8080 or udp port 5353"

# No color (for piping to a file)
sudo python3 sniffer.py --no-color | tee capture.txt
```

### Full CLI reference

```
usage: sniffer.py [-h] [-i INTERFACE] [-p {http,https,dns,icmp,arp} ...]
                  [-f FILTER] [-c COUNT] [-o OUTPUT_DIR] [--json]
                  [--stats-interval N] [--no-color] [-v] [-q]

  -i, --interface       Network interface (auto-detected if omitted)
  -p, --protocols       Protocols to capture [default: http https dns]
  -f, --filter          Raw BPF filter (overrides --protocols)
  -c, --count           Stop after N packets (0 = unlimited)
  -o, --output-dir      Log directory [default: logs/]
  --json                Also write JSON-lines log
  --stats-interval N    Print live stats every N seconds (0 = off)
  --no-color            Disable ANSI colors
  -v, --verbose         Show all TCP packets, not just HTTP
  -q, --quiet           Suppress per-packet terminal output
```

---

## Log File Formats

All logs are written to `logs/` by default.

### `packet_log.csv`

| Column | Description |
|---|---|
| timestamp | UTC ISO-8601 |
| src_ip / dst_ip | IP addresses |
| protocol | HTTP, HTTPS/TLS, DNS, ICMP, ARP |
| src_port / dst_port | Transport ports |
| http_method | GET, POST, etc. |
| http_url | Request path |
| http_host | HTTP Host header |
| tls_sni | TLS Server Name Indication |
| dns_query | Queried domain |
| icmp_type / icmp_code | ICMP type/code numbers |
| arp_op / arp_sender / arp_target | ARP operation and IPs |
| pkt_len | Packet size in bytes |

### `packet_log.jsonl` (with `--json`)

One JSON object per line with the same fields.

### `sniffer_app.log`

Application-level events (errors, start/stop). Rotates at 5 MB, keeps 3 backups.

---

## File Structure

```
.
├── sniffer.py          # Main script (single file)
├── requirements.txt    # Dependencies
├── README.md           # This file
└── logs/               # Created at runtime
    ├── packet_log.csv
    ├── packet_log.jsonl  (if --json)
    └── sniffer_app.log
```

---

## Ethical & Legal Warning

**Unauthorized packet capture is illegal in many jurisdictions.**  
You must have explicit permission from the network owner before running this tool.  
It is provided **exclusively** for educational use, security training, network troubleshooting, and authorized penetration testing.

By using this software you agree that you understand and comply with all applicable laws. The author assumes **no liability** for misuse.

---

## License

MIT License
