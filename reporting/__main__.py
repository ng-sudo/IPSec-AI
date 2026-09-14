from __future__ import annotations

import argparse
import json
from pathlib import Path

from .generator import write_reports


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate IPSecAI executive and technical reports")
    parser.add_argument("analysis_json", type=Path, help="JSON returned by the FastAPI analysis endpoint")
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    analysis = json.loads(args.analysis_json.read_text(encoding="utf-8"))
    bundle = write_reports(analysis, args.output_dir)
    print(json.dumps({"capture_id": bundle.executive.capture_id, "output_dir": str(args.output_dir), "reports": list(bundle.as_markdown_files())}, indent=2))


if __name__ == "__main__":
    main()
