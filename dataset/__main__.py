from __future__ import annotations

import argparse
import json
from pathlib import Path

from .models import DatasetManifest
from .pipeline import build_dataset, validate_manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Build and validate leakage-safe IPsec ESP datasets")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build", help="build dataset manifests from raw PCAP captures")
    build.add_argument("raw_dir", type=Path)
    build.add_argument("output_dir", type=Path)
    build.add_argument("--seed", type=int, default=26160)
    build.add_argument("--train-ratio", type=float, default=0.70)
    build.add_argument("--validation-ratio", type=float, default=0.15)
    build.add_argument("--test-ratio", type=float, default=0.15)

    validate = subparsers.add_parser("validate", help="validate an existing manifest")
    validate.add_argument("manifest", type=Path)

    args = parser.parse_args()
    if args.command == "build":
        manifest = build_dataset(
            args.raw_dir,
            args.output_dir,
            seed=args.seed,
            split_ratios={
                "train": args.train_ratio,
                "validation": args.validation_ratio,
                "test": args.test_ratio,
            },
        )
        print(json.dumps({"records": len(manifest.records), "output_dir": str(args.output_dir)}, indent=2))
        return

    manifest = DatasetManifest.model_validate_json(args.manifest.read_text(encoding="utf-8"))
    report = validate_manifest(manifest)
    print(report.model_dump_json(indent=2))
    raise SystemExit(0 if report.valid else 1)


if __name__ == "__main__":
    main()
