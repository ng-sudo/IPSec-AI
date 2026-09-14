from __future__ import annotations

import argparse
import json
from pathlib import Path

from dataset.models import DatasetRecord

from .pipeline import evaluate_bundle, load_bundle, predict_record, train_classifier


def main() -> None:
    parser = argparse.ArgumentParser(description="Train and use the encrypted ESP traffic classifier")
    subparsers = parser.add_subparsers(dest="command", required=True)

    train = subparsers.add_parser("train", help="select, evaluate, and persist a classifier")
    train.add_argument("manifest", type=Path)
    train.add_argument("model", type=Path)
    train.add_argument("--seed", type=int, default=26160)

    predict = subparsers.add_parser("predict", help="predict one dataset record")
    predict.add_argument("model", type=Path)
    predict.add_argument("record", type=Path, help="JSON file containing one DatasetRecord")

    evaluate = subparsers.add_parser("evaluate", help="evaluate a persisted model on the test split")
    evaluate.add_argument("model", type=Path)
    evaluate.add_argument("manifest", type=Path)

    args = parser.parse_args()
    if args.command == "train":
        bundle = train_classifier(args.manifest, args.model, seed=args.seed)
        print(json.dumps({
            "model": str(args.model),
            "model_name": bundle.model_name,
            "model_version": bundle.model_version,
            "validation": bundle.validation_metrics,
            "test": bundle.test_metrics,
        }, indent=2))
    elif args.command == "predict":
        record = DatasetRecord.model_validate_json(args.record.read_text(encoding="utf-8"))
        print(json.dumps(predict_record(args.model, record).to_dict(), indent=2))
    else:
        print(json.dumps(evaluate_bundle(args.model, args.manifest), indent=2))


if __name__ == "__main__":
    main()
