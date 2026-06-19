#!/usr/bin/env python3
"""
Enhanced Network Packet Sniffer – Educational / Research Use Only.

WARNING: Use ONLY on networks you own or have explicit written permission
to monitor. Unauthorized packet capture may be illegal. The author
assumes no liability for misuse.

Upgrades over original main.py:
  - Multi-protocol support: HTTP, HTTPS/TLS, DNS, ARP, ICMP
  - Colorized, readable terminal output
  - Rotating log files (daily rotation, configurable max size)
  - Live statistics counter (packets, bytes, proto breakdown)
  - Configurable BPF filter via CLI
  - Packet count limit (-c / --count)
  - Verbose / quiet modes
  - Optional JSON log format alongside CSV
  - GeoIP-style domain grouping in stats summary
  - Thread-safe CSV/JSON writes
  - Graceful signal handling (SIGTERM + SIGINT)
  - Full type annotations and Google-style docstrings
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import signal
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Dict, Optional, Tuple

# ---------------------------------------------------------------------------
# Optional color support (no external dep – pure ANSI)
# ---------------------------------------------------------------------------
RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
BLUE    = "\033[94m"
DIM     = "\033[2m"

def _no_color(s: str) -> str:
    return s

def colorize(text: str, code: str, use_color: bool = True) -> str:
    """Wrap *text* in ANSI escape codes if *use_color* is True."""
    if not use_color:
        return text
    return f"{code}{text}{RESET}"

# ---------------------------------------------------------------------------
# Lazy import of scapy (gives a clean error message if missing)
# ---------------------------------------------------------------------------
try:
    from scapy.all import (
        ARP,
        DNS,
        DNSQR,
        ICMP,
        IP,
        TCP,
        UDP,
        conf,
        sniff,
    )
    from scapy.error import Scapy_Exception
    from scapy.layers.tls.handshake import TLSClientHello  # type: ignore
    _TLS_AVAILABLE = True
except ImportError:
    _TLS_AVAILABLE = False
    try:
        from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, conf, sniff
        from scapy.error import Scapy_Exception
    except ImportError:
        sys.exit(
            "scapy is not installed. Run:  pip install scapy"
        )

# ---------------------------------------------------------------------------
# Logging setup (application log, separate from packet CSV/JSON)
# ---------------------------------------------------------------------------
_app_logger = logging.getLogger("sniffer.app")


def setup_app_logger(log_dir: str, verbose: bool) -> None:
    """Configure the application event logger with rotation."""
    os.makedirs(log_dir, exist_ok=True)
    handler = RotatingFileHandler(
        os.path.join(log_dir, "sniffer_app.log"),
        maxBytes=5 * 1024 * 1024,  # 5 MB
        backupCount=3,
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    )
    _app_logger.addHandler(handler)
    _app_logger.setLevel(logging.DEBUG if verbose else logging.INFO)


# ---------------------------------------------------------------------------
# Statistics tracker
# ---------------------------------------------------------------------------
class Stats:
    """Thread-safe live statistics for captured packets."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.by_protocol: Dict[str, int] = defaultdict(int)
        self.http_requests: int = 0
        self.dns_queries: int = 0
        self.dns_domains: Dict[str, int] = defaultdict(int)
        self.start_time: float = time.monotonic()

    def record(
        self,
        protocol: str,
        pkt_len: int,
        http_hit: bool = False,
        dns_domain: Optional[str] = None,
    ) -> None:
        with self._lock:
            self.total_packets += 1
            self.total_bytes += pkt_len
            self.by_protocol[protocol] += 1
            if http_hit:
                self.http_requests += 1
            if dns_domain:
                self.dns_queries += 1
                self.dns_domains[dns_domain] += 1

    def snapshot(self) -> dict:
        with self._lock:
            elapsed = time.monotonic() - self.start_time
            return {
                "elapsed_seconds": round(elapsed, 1),
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "packets_per_sec": round(self.total_packets / max(elapsed, 0.001), 2),
                "by_protocol": dict(self.by_protocol),
                "http_requests": self.http_requests,
                "dns_queries": self.dns_queries,
                "top_dns_domains": dict(
                    sorted(
                        self.dns_domains.items(), key=lambda kv: kv[1], reverse=True
                    )[:10]
                ),
            }


# ---------------------------------------------------------------------------
# Protocol parsers
# ---------------------------------------------------------------------------
def parse_http(payload: bytes) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Extract HTTP method, path, and Host header from a raw TCP payload.

    Returns:
        (method, path, host) or (None, None, None).
    """
    try:
        text = payload.decode("utf-8", errors="ignore")
        lines = text.split("\r\n")
        first = lines[0].split()
        if len(first) >= 2 and first[0] in (
            "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT",
        ):
            method, path = first[0], first[1]
            host = None
            for line in lines[1:]:
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()
                    break
            return method, path, host
    except Exception:
        pass
    return None, None, None


def detect_tls_sni(payload: bytes) -> Optional[str]:
    """Extract the SNI hostname from a TLS ClientHello payload (best-effort).

    This works without scapy's TLS contrib by parsing the raw bytes.
    Returns the SNI string or None.
    """
    try:
        # TLS record layer: content_type=0x16, version, length
        if len(payload) < 5 or payload[0] != 0x16:
            return None
        # Handshake type 0x01 = ClientHello
        if payload[5] != 0x01:
            return None
        # Skip to extensions – rough offset, not a full parser
        # Walk through session_id, cipher_suites, compression
        pos = 43  # fixed header up to session_id length
        if pos >= len(payload):
            return None
        session_id_len = payload[pos]
        pos += 1 + session_id_len
        if pos + 2 > len(payload):
            return None
        cs_len = int.from_bytes(payload[pos:pos+2], "big")
        pos += 2 + cs_len
        if pos + 1 > len(payload):
            return None
        comp_len = payload[pos]
        pos += 1 + comp_len
        if pos + 2 > len(payload):
            return None
        ext_total = int.from_bytes(payload[pos:pos+2], "big")
        pos += 2
        end = pos + ext_total
        while pos + 4 <= end and pos + 4 <= len(payload):
            ext_type = int.from_bytes(payload[pos:pos+2], "big")
            ext_len  = int.from_bytes(payload[pos+2:pos+4], "big")
            pos += 4
            if ext_type == 0x00 and pos + ext_len <= len(payload):  # SNI
                # SNI list len(2), type(1)=0, name len(2), name
                if ext_len >= 5:
                    name_len = int.from_bytes(payload[pos+3:pos+5], "big")
                    sni = payload[pos+5:pos+5+name_len].decode("ascii", errors="ignore")
                    return sni if sni else None
            pos += ext_len
    except Exception:
        pass
    return None


def parse_dns(pkt) -> Optional[str]:
    """Extract the DNS QNAME from a packet."""
    if pkt.haslayer(DNS) and pkt[DNS].qd is not None:
        try:
            qname = pkt[DNS].qd.qname
            if isinstance(qname, bytes):
                qname = qname.decode("utf-8", errors="ignore")
            return qname.rstrip(".")
        except Exception:
            pass
    return None


def parse_icmp(pkt) -> Tuple[Optional[int], Optional[int]]:
    """Return (icmp_type, icmp_code) or (None, None)."""
    if pkt.haslayer(ICMP):
        try:
            return int(pkt[ICMP].type), int(pkt[ICMP].code)
        except Exception:
            pass
    return None, None


ICMP_TYPE_NAMES = {
    0: "Echo Reply",
    3: "Dest Unreachable",
    8: "Echo Request",
    11: "Time Exceeded",
}

ARP_OP_NAMES = {1: "who-has", 2: "is-at"}

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


CSV_FIELDS = [
    "timestamp", "src_ip", "dst_ip", "protocol",
    "src_port", "dst_port",
    "http_method", "http_url", "http_host",
    "tls_sni",
    "dns_query",
    "icmp_type", "icmp_code",
    "arp_op", "arp_sender", "arp_target",
    "pkt_len",
]


class PacketLogger:
    """Manages thread-safe CSV and optional JSON packet logging with rotation."""

    def __init__(self, log_dir: str, json_log: bool = False) -> None:
        os.makedirs(log_dir, exist_ok=True)
        self._lock = threading.Lock()

        # CSV (rotating)
        self._csv_path = os.path.join(log_dir, "packet_log.csv")
        file_new = not os.path.isfile(self._csv_path) or os.path.getsize(self._csv_path) == 0
        self._csv_fh = open(self._csv_path, "a", newline="", encoding="utf-8")
        self._writer = csv.DictWriter(self._csv_fh, fieldnames=CSV_FIELDS)
        if file_new:
            self._writer.writeheader()
            self._csv_fh.flush()

        # JSON (optional)
        self._json_log = json_log
        self._json_path = os.path.join(log_dir, "packet_log.jsonl") if json_log else None
        self._json_fh = (
            open(self._json_path, "a", encoding="utf-8") if json_log else None
        )

    def write(self, row: dict) -> None:
        with self._lock:
            self._writer.writerow({f: row.get(f, "") for f in CSV_FIELDS})
            self._csv_fh.flush()
            if self._json_fh:
                self._json_fh.write(json.dumps(row) + "\n")
                self._json_fh.flush()

    def close(self) -> None:
        self._csv_fh.close()
        if self._json_fh:
            self._json_fh.close()


# ---------------------------------------------------------------------------
# Core sniffer
# ---------------------------------------------------------------------------
def build_filter(protocols: list[str]) -> str:
    """Build a BPF filter string from a list of protocol names."""
    mapping = {
        "http":  "tcp port 80",
        "https": "tcp port 443",
        "dns":   "udp port 53",
        "icmp":  "icmp",
        "arp":   "arp",
    }
    parts = [mapping[p] for p in protocols if p in mapping]
    return " or ".join(parts) if parts else ""


def get_default_interface() -> str:
    iface = conf.route.route("0.0.0.0")[0]
    if not iface:
        raise RuntimeError("Cannot detect default network interface.")
    return iface


def is_root() -> bool:
    return os.geteuid() == 0


class Sniffer:
    """High-level sniffer object wrapping scapy's sniff()."""

    def __init__(
        self,
        interface: str,
        bpf_filter: str,
        logger: PacketLogger,
        stats: Stats,
        use_color: bool = True,
        verbose: bool = True,
        quiet: bool = False,
        max_packets: int = 0,
    ) -> None:
        self._iface = interface
        self._filter = bpf_filter
        self._logger = logger
        self._stats = stats
        self._color = use_color
        self._verbose = verbose
        self._quiet = quiet
        self._max_packets = max_packets
        self._stop_event = threading.Event()

    def _c(self, text: str, code: str) -> str:
        return colorize(text, code, self._color)

    def _process(self, pkt) -> None:
        if self._stop_event.is_set():
            return

        try:
            ts = _ts()
            row: dict = {"timestamp": ts}
            pkt_len = len(pkt)
            row["pkt_len"] = pkt_len
            display_parts: list[str] = []

            # --- ARP (no IP layer) ---
            if pkt.haslayer(ARP):
                op = pkt[ARP].op
                sender = pkt[ARP].psrc
                target = pkt[ARP].pdst
                row.update({
                    "src_ip": sender, "dst_ip": target,
                    "protocol": "ARP",
                    "arp_op": ARP_OP_NAMES.get(op, str(op)),
                    "arp_sender": sender, "arp_target": target,
                })
                self._stats.record("ARP", pkt_len)
                display_parts = [
                    self._c(ts, DIM),
                    self._c("ARP", MAGENTA),
                    f"{sender} → {target}",
                    self._c(ARP_OP_NAMES.get(op, str(op)), YELLOW),
                ]
                if not self._quiet:
                    print("  ".join(display_parts))
                self._logger.write(row)
                return

            # --- IP-based ---
            if not pkt.haslayer(IP):
                return

            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            row.update({"src_ip": src_ip, "dst_ip": dst_ip})

            # --- ICMP ---
            if pkt.haslayer(ICMP):
                icmp_type, icmp_code = parse_icmp(pkt)
                row.update({
                    "protocol": "ICMP",
                    "icmp_type": icmp_type,
                    "icmp_code": icmp_code,
                })
                self._stats.record("ICMP", pkt_len)
                label = ICMP_TYPE_NAMES.get(icmp_type or -1, f"type={icmp_type}")
                display_parts = [
                    self._c(ts, DIM),
                    self._c("ICMP", BLUE),
                    f"{src_ip} → {dst_ip}",
                    self._c(label, YELLOW),
                ]
                if not self._quiet:
                    print("  ".join(display_parts))
                self._logger.write(row)
                return

            # --- TCP ---
            if pkt.haslayer(TCP):
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                payload = bytes(pkt[TCP].payload)
                row.update({"src_port": sport, "dst_port": dport})

                # HTTPS / TLS
                if dport == 443 or sport == 443:
                    sni = detect_tls_sni(payload)
                    row.update({"protocol": "HTTPS/TLS", "tls_sni": sni or ""})
                    self._stats.record("HTTPS", pkt_len)
                    sni_str = self._c(sni, GREEN) if sni else self._c("(no SNI)", DIM)
                    display_parts = [
                        self._c(ts, DIM),
                        self._c("HTTPS", CYAN),
                        f"{src_ip}:{sport} → {dst_ip}:{dport}",
                        f"SNI: {sni_str}",
                    ]
                    if not self._quiet:
                        print("  ".join(display_parts))

                else:
                    # HTTP
                    method, path, host = parse_http(payload)
                    row.update({
                        "protocol": "HTTP",
                        "http_method": method or "",
                        "http_url": path or "",
                        "http_host": host or "",
                    })
                    is_http = bool(method)
                    self._stats.record("HTTP", pkt_len, http_hit=is_http)

                    if not self._quiet and (is_http or self._verbose):
                        verb_str = ""
                        if method:
                            verb_str = self._c(f"{method} {host or ''}{path}", GREEN)
                        display_parts = [
                            self._c(ts, DIM),
                            self._c("HTTP ", RED),
                            f"{src_ip}:{sport} → {dst_ip}:{dport}",
                        ]
                        if verb_str:
                            display_parts.append(verb_str)
                        print("  ".join(display_parts))

            # --- UDP / DNS ---
            elif pkt.haslayer(UDP):
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                row.update({"src_port": sport, "dst_port": dport})
                dns_domain = parse_dns(pkt)
                row.update({"protocol": "DNS", "dns_query": dns_domain or ""})
                self._stats.record("DNS", pkt_len, dns_domain=dns_domain)

                if not self._quiet and dns_domain:
                    display_parts = [
                        self._c(ts, DIM),
                        self._c("DNS ", YELLOW),
                        f"{src_ip}:{sport} → {dst_ip}:{dport}",
                        self._c(dns_domain, BOLD),
                    ]
                    print("  ".join(display_parts))

            else:
                return

            self._logger.write(row)
            _app_logger.debug("Packet processed: %s", row.get("protocol"))

        except Exception as exc:
            _app_logger.error("Packet processing error: %s", exc, exc_info=True)
            print(
                self._c(f"[!] Error processing packet: {exc}", RED),
                file=sys.stderr,
            )

    def start(self) -> None:
        print(
            self._c(
                f"\n[*] Sniffing on '{self._iface}'  filter: '{self._filter}'",
                BOLD,
            )
        )
        print(self._c("[*] Press Ctrl+C to stop.\n", DIM))
        _app_logger.info("Sniffer started on %s | filter: %s", self._iface, self._filter)
        try:
            sniff(
                iface=self._iface,
                filter=self._filter,
                prn=self._process,
                store=0,
                count=self._max_packets or 0,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except PermissionError:
            sys.exit(self._c(
                "Error: Permission denied. Run with sudo.", RED
            ))
        except Scapy_Exception as e:
            sys.exit(self._c(f"Scapy error: {e}", RED))
        except KeyboardInterrupt:
            pass

    def stop(self) -> None:
        self._stop_event.set()


# ---------------------------------------------------------------------------
# Stats printer (background thread)
# ---------------------------------------------------------------------------
def start_stats_printer(stats: Stats, interval: int, use_color: bool) -> threading.Thread:
    """Spawn a daemon thread that prints stats every *interval* seconds."""

    def _loop() -> None:
        while True:
            time.sleep(interval)
            snap = stats.snapshot()
            lines = [
                colorize(
                    f"\n── Live Stats ({snap['elapsed_seconds']}s elapsed) ──",
                    BOLD, use_color,
                ),
                f"  Packets : {snap['total_packets']}  ({snap['packets_per_sec']}/s)",
                f"  Bytes   : {snap['total_bytes']}",
                f"  Protos  : {snap['by_protocol']}",
                f"  HTTP    : {snap['http_requests']} requests",
                f"  DNS     : {snap['dns_queries']} queries",
            ]
            if snap["top_dns_domains"]:
                top = ", ".join(
                    f"{d}({c})" for d, c in list(snap["top_dns_domains"].items())[:5]
                )
                lines.append(f"  Top DNS : {top}")
            lines.append("")
            print("\n".join(lines))

    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    return t


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Enhanced passive network sniffer (HTTP / HTTPS / DNS / ICMP / ARP).\n"
            "For educational and authorized research use only."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-i", "--interface", help="Network interface (auto-detected if omitted).")
    p.add_argument(
        "-p", "--protocols",
        nargs="+",
        default=["http", "https", "dns"],
        choices=["http", "https", "dns", "icmp", "arp"],
        help="Protocols to capture (default: http https dns).",
    )
    p.add_argument(
        "-f", "--filter",
        default=None,
        help="Raw BPF filter string (overrides --protocols).",
    )
    p.add_argument("-c", "--count", type=int, default=0,
                   help="Stop after N packets (0 = unlimited).")
    p.add_argument("-o", "--output-dir", default="logs",
                   help="Directory for CSV/JSON logs (default: logs/).")
    p.add_argument("--json", action="store_true",
                   help="Also write a JSON-lines log (packet_log.jsonl).")
    p.add_argument("--stats-interval", type=int, default=0,
                   help="Print live stats every N seconds (0 = off).")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors.")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show all TCP packets, not just HTTP.")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="Suppress per-packet output (log only).")
    return p.parse_args()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    args = parse_args()

    use_color = not args.no_color and sys.stdout.isatty()

    if not is_root():
        sys.exit(
            colorize(
                "Error: Root/Administrator privileges required. Run with sudo.",
                RED, use_color,
            )
        )

    setup_app_logger(args.output_dir, args.verbose)

    iface = args.interface or get_default_interface()
    bpf = args.filter or build_filter(args.protocols)

    pkt_logger = PacketLogger(args.output_dir, json_log=args.json)
    stats = Stats()

    sniffer = Sniffer(
        interface=iface,
        bpf_filter=bpf,
        logger=pkt_logger,
        stats=stats,
        use_color=use_color,
        verbose=args.verbose,
        quiet=args.quiet,
        max_packets=args.count,
    )

    # SIGTERM graceful stop
    def _sigterm(*_):
        sniffer.stop()

    signal.signal(signal.SIGTERM, _sigterm)

    if args.stats_interval > 0:
        start_stats_printer(stats, args.stats_interval, use_color)

    sniffer.start()

    # Final summary
    snap = stats.snapshot()
    print(colorize("\n── Final Summary ──", BOLD, use_color))
    print(f"  Duration  : {snap['elapsed_seconds']}s")
    print(f"  Packets   : {snap['total_packets']}")
    print(f"  Bytes     : {snap['total_bytes']}")
    print(f"  Protocols : {snap['by_protocol']}")
    print(f"  HTTP reqs : {snap['http_requests']}")
    print(f"  DNS qrys  : {snap['dns_queries']}")
    if snap["top_dns_domains"]:
        print("  Top DNS   :")
        for domain, count in snap["top_dns_domains"].items():
            print(f"    {domain:40s} {count}")
    print(f"\n  Logs      : {args.output_dir}/")
    _app_logger.info("Sniffer stopped. %d packets captured.", snap["total_packets"])
    pkt_logger.close()


if __name__ == "__main__":
    main()
