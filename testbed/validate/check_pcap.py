#!/usr/bin/env python3
"""Validate that a generated PCAP contains IPsec traffic for a scenario.

This script is intentionally conservative: it does not claim protocol
classification beyond confirming packet capture existence and the presence of
expected IPsec-related traffic.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def _count_packets_with_tshark(path: Path) -> tuple[int, int]:
    """Count packets and IPsec-like packets via tshark if available."""
    try:
        cmd = [
            "tshark",
            "-r",
            str(path),
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-Y",
            "udp.port == 500 || udp.port == 4500 || ip.proto == 50 || ip.proto == 51 || ipv6.nxt == 50 || ipv6.nxt == 51",
        ]
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
        lines = [line.strip() for line in out.splitlines() if line.strip()]
        return sum(1 for _ in lines), len(lines)
    except (FileNotFoundError, subprocess.CalledProcessError):
        return 0, 0


def _count_packets_with_tcpdump(path: Path) -> tuple[int, int]:
    """Count packets and IPsec-like packets via tcpdump if available."""
    try:
        cmd = [
            "tcpdump",
            "-nn",
            "-r",
            str(path),
            "udp port 500 or udp port 4500 or proto 50 or proto 51",
        ]
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
        lines = [line.strip() for line in out.splitlines() if line.strip()]
        return max(0, len(lines)), len(lines)
    except (FileNotFoundError, subprocess.CalledProcessError):
        return 0, 0


def _count_packets_with_scapy(path: Path) -> tuple[int, int]:
    """Fallback counts using Scapy when available."""
    try:
        from scapy.all import IP, IPv6, TCP, UDP, rdpcap
    except ImportError:
        return 0, 0

    packets = rdpcap(str(path))
    total = len(packets)
    ipsec_matches = 0
    for pkt in packets:
        # Basic protocol checks without doing classification beyond transport.
        if IP in pkt and (pkt[IP].proto in (50, 51)):
            ipsec_matches += 1
            continue
        if IPv6 in pkt and (pkt[IPv6].nxt in (50, 51)):
            ipsec_matches += 1
            continue
        if UDP in pkt and pkt[UDP].dport in (500, 4500):
            ipsec_matches += 1
    return total, ipsec_matches


def validate_pcap(path: Path) -> int:
    if not path.exists():
        print(f"ERROR: PCAP file not found: {path}", file=sys.stderr)
        return 1

    if path.stat().st_size <= 0:
        print(f"ERROR: PCAP file is empty: {path}", file=sys.stderr)
        return 1

    total_packets, ipsec_packets = _count_packets_with_scapy(path)
    if total_packets == 0 and ipsec_packets == 0:
        total_packets, ipsec_packets = _count_packets_with_tshark(path)
    if total_packets == 0 and ipsec_packets == 0:
        total_packets, ipsec_packets = _count_packets_with_tcpdump(path)

    if total_packets == 0:
        print(f"ERROR: No packets were captured in {path}", file=sys.stderr)
        return 1

    if ipsec_packets == 0:
        print(
            f"ERROR: Captured packets do not include expected IPsec traffic in {path}",
            file=sys.stderr,
        )
        return 1

    print(f"PCAP OK: {path}")
    print(f"  total_packets: {total_packets}")
    print(f"  ipsec_like_packets: {ipsec_packets}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate a generated IPsec PCAP by confirming it has packets and IPsec-related traffic."
    )
    parser.add_argument("pcap", type=Path, help="Path to the .pcap file to validate")
    args = parser.parse_args()
    return validate_pcap(args.pcap)


if __name__ == "__main__":
    sys.exit(main())
