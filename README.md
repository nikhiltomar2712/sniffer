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
