#!/usr/bin/env python3
"""
Ethical network packet sniffer – educational/research purposes only.

WARNING: This tool is intended for use ONLY on networks you own or for
which you have explicit written permission to monitor. Unauthorized
packet capture may be illegal in your jurisdiction. The author assumes
no liability for misuse.
"""

import argparse
import csv
import os
import sys
from datetime import datetime, timezone
from typing import Optional, Tuple

from scapy.all import (
    sniff,
    IP,
    TCP,
    UDP,
    DNS,
    DNSQR,
    conf,
)
from scapy.error import Scapy_Exception


# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------

def get_default_interface() -> str:
    """
    Return the name of the default network interface using the system's
    routing table.

    Returns
    -------
    str
        Interface name (e.g., 'eth0', 'en0').
    """
    # conf.route.route("0.0.0.0") returns (interface, gateway, source)
    iface = conf.route.route("0.0.0.0")[0]
    if not iface:
        raise RuntimeError("Could not determine default network interface.")
    return iface


def is_root() -> bool:
    """Return True if the script is running with root/Administrator privileges."""
    return os.geteuid() == 0


def parse_http(payload: bytes) -> Tuple[Optional[str], Optional[str]]:
    """
    Try to extract HTTP method and URL from a raw TCP payload.

    Parameters
    ----------
    payload : bytes
        The packet payload.

    Returns
    -------
    tuple
        (method, url) or (None, None) if not an HTTP request.
    """
    try:
        # Only decode the first line (typical HTTP request)
        first_line = payload.split(b"\r\n")[0].decode("utf-8", errors="ignore")
        parts = first_line.split()
        # Expect e.g. "GET /index.html HTTP/1.1"
        if len(parts) >= 3 and parts[0] in (
            "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"
        ):
            return parts[0], parts[1]
    except (UnicodeDecodeError, IndexError):
        pass
    return None, None


def parse_dns(packet) -> Optional[str]:
    """
    Extract the DNS query name (QNAME) from a packet.

    Parameters
    ----------
    packet : scapy.packet.Packet
        A packet that has a DNS layer.

    Returns
    -------
    str or None
        The queried domain name (without trailing dot), or None.
    """
    if packet.haslayer(DNS) and packet[DNS].qd is not None:
        try:
            qname = packet[DNS].qd.qname
            if isinstance(qname, bytes):
                qname = qname.decode("utf-8", errors="ignore")
            # Remove the trailing dot if present
            return qname.rstrip(".")
        except Exception:
            pass
    return None


# ----------------------------------------------------------------------
# Main packet processor
# ----------------------------------------------------------------------

def main(interface: str) -> None:
    """
    Start sniffing and log matching packets.

    Parameters
    ----------
    interface : str
        Name of the network interface to sniff on.
    """
    # ----- Privilege check -----
    if not is_root():
        sys.exit("Error: Root/Administrator privileges required. Please run with sudo.")

    # ----- CSV setup -----
    csv_filename = "packet_log.csv"
    fieldnames = [
        "timestamp",
        "src_ip",
        "dst_ip",
        "protocol",
        "src_port",
        "dst_port",
        "http_method",
        "http_url",
        "dns_query",
    ]

    # Write CSV header if file is new/empty
    file_exists = os.path.isfile(csv_filename)
    write_header = not file_exists or os.path.getsize(csv_filename) == 0

    csv_file = open(csv_filename, "a", newline="", encoding="utf-8")
    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
    if write_header:
        writer.writeheader()
        csv_file.flush()

    # ----- Packet callback -----
    def process_packet(pkt) -> None:
        """Callback executed by scapy's sniff() for each captured packet."""
        try:
            # Common info
            timestamp = datetime.now(timezone.utc).isoformat()
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            if pkt.haslayer(TCP):
                proto = "TCP"
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                payload = bytes(pkt[TCP].payload)
                http_method, http_url = parse_http(payload)
                dns_query = None
            elif pkt.haslayer(UDP):
                proto = "UDP"
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                http_method = http_url = None
                dns_query = parse_dns(pkt)
            else:
                # Should not happen due to BPF filter
                return

            # Human-readable output
            display = f"{timestamp} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} [{proto}]"
            if http_method:
                display += f" | HTTP {http_method} {http_url}"
            if dns_query:
                display += f" | DNS query: {dns_query}"
            print(display)

            # CSV log
            writer.writerow({
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": proto,
                "src_port": src_port,
                "dst_port": dst_port,
                "http_method": http_method or "",
                "http_url": http_url or "",
                "dns_query": dns_query or "",
            })
            csv_file.flush()

        except Exception as exc:
            # Never let a single bad packet kill the whole sniffer
            print(f"[!] Error processing packet: {exc}", file=sys.stderr)

    # ----- Start sniffing -----
    bpf_filter = "tcp port 80 or udp port 53"
    print(f"[*] Starting capture on interface '{interface}' with filter '{bpf_filter}'")
    print("[*] Press Ctrl+C to stop.\n")

    try:
        sniff(
            iface=interface,
            filter=bpf_filter,
            prn=process_packet,
            store=0,          # Don't keep packets in memory
        )
    except PermissionError:
        sys.exit("Error: Permission denied. Ensure you have CAP_NET_RAW or run with sudo.")
    except Scapy_Exception as e:
        sys.exit(f"Scapy error: {e}")
    except KeyboardInterrupt:
        print("\n[*] Sniffing stopped by user.")
    finally:
        csv_file.close()
        print(f"[*] CSV log written to {csv_filename}")


# ----------------------------------------------------------------------
# Command-line interface
# ----------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Passive network sniffer for HTTP/DNS traffic (educational only)."
    )
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to sniff on (auto-detected if omitted).",
        default=None,
    )
    args = parser.parse_args()

    iface = args.interface or get_default_interface()
    main(iface)
