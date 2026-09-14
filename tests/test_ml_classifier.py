from __future__ import annotations

import json
from pathlib import Path

import pytest

from dataset.models import DatasetManifest, DatasetRecord
from ml_classifier.pipeline import evaluate_bundle, load_bundle, predict_record, train_classifier


def _record(scenario_id: str, capture_id: str, traffic_type: str, split: str, offset: float) -> DatasetRecord:
    return DatasetRecord(
        capture_id=capture_id,
        scenario_id=scenario_id,
        pcap_file=f"{capture_id}.pcap",
        traffic_type=traffic_type,
        vpn_configuration={"ip_version": 4, "ipsec_mode": "tunnel"},
        protocol_metadata={"esp_packets": 10},
        flow_features={
            "packet_count": 10 + offset,
            "byte_count": 1000 + offset * 10,
            "packet_size_mean": 100 + offset,
            "inter_arrival_mean": 0.01 + offset / 1000,
            "flow_duration_seconds": 1 + offset / 10,
            "packets_per_second": 10 + offset,
            "bytes_per_second": 1000 + offset * 10,
            "esp_packet_ratio": 1.0,
        },
        labels={"traffic_type": traffic_type},
        split=split,
    )


def _manifest() -> DatasetManifest:
    records = []
    traffic_types = ("icmp", "tcp", "udp", "iperf")
    for index, split in enumerate(("train", "validation", "test")):
        scenario = f"scenario-{index}"
        for label_index, traffic_type in enumerate(traffic_types):
            records.append(_record(scenario, f"{scenario}-{traffic_type}", traffic_type, split, label_index))
    return DatasetManifest(
        split_seed=26160,
        split_ratios={"train": 0.7, "validation": 0.15, "test": 0.15},
        records=records,
    )


def test_train_persist_predict_and_evaluate(tmp_path):
    manifest_path = tmp_path / "manifest.json"
    model_path = tmp_path / "esp-classifier.joblib"
    manifest_path.write_text(json.dumps(_manifest().model_dump()), encoding="utf-8")

    bundle = train_classifier(manifest_path, model_path, seed=3)
    loaded = load_bundle(model_path)
    prediction = predict_record(loaded, _manifest().records[0])
    test_metrics = evaluate_bundle(loaded, manifest_path)

    assert model_path.is_file()
    assert bundle.model_name in {"random_forest", "gradient_boosting"}
    assert bundle.validation_metrics["selected_model"] == bundle.model_name
    assert set(bundle.test_metrics) >= {"accuracy", "precision_macro", "recall_macro", "f1_macro", "confusion_matrix"}
    assert prediction.predicted_traffic_type in {"icmp", "tcp", "udp", "iperf"}
    assert 0.0 <= prediction.confidence <= 1.0
    assert prediction.model_version == "ipsec-esp-traffic-classifier/1.0"
    assert test_metrics["sample_count"] == 4


def test_training_rejects_scenario_leakage(tmp_path):
    manifest = _manifest()
    manifest.records[0] = manifest.records[0].model_copy(update={"split": "test"})
    manifest_path = tmp_path / "leaky.json"
    model_path = tmp_path / "model.joblib"
    manifest_path.write_text(json.dumps(manifest.model_dump()), encoding="utf-8")

    with pytest.raises(ValueError, match="scenario leakage"):
        train_classifier(manifest_path, model_path)
