from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analyzer import analyze_pcap


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze a PCAP/PCAPNG file for observable IPsec metadata.")
    parser.add_argument("pcap", type=Path, help="Path to a PCAP or PCAPNG file")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    args = parser.parse_args()

    result = analyze_pcap(args.pcap)
    data = json.loads(result.model_dump_json())
    if args.pretty:
        print(json.dumps(data, indent=2, sort_keys=True))
    else:
        print(json.dumps(data, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
