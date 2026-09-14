from __future__ import annotations

import json
from pathlib import Path

import pytest
from scapy.all import ESP, IP, Raw, wrpcap

from dataset.models import DatasetManifest, DatasetRecord
from dataset.pipeline import build_dataset, load_capture_record, validate_manifest


def _write_capture(raw_dir: Path, scenario_id: str, traffic_type: str) -> None:
    pcap = raw_dir / f"{scenario_id}_{traffic_type}.pcap"
    wrpcap(str(pcap), [IP(src="10.0.0.1", dst="10.0.0.2", proto=50) / ESP(spi=1, seq=1) / Raw(load=b"encrypted")])
    meta = {
        "scenario_id": scenario_id,
        "capture_id": f"{scenario_id}_{traffic_type}",
        "traffic_type": traffic_type,
        "labels": {
            "ipsec_mode": "tunnel",
            "ike_version": 2,
            "encryption": "aes256gcm16",
            "integrity": None,
            "prf": "sha256",
            "dh_group": "modp2048",
            "pfs_enabled": True,
            "ip_version": 4,
            "auth_method": "psk",
            "traffic_types": [traffic_type],
        },
    }
    (raw_dir / f"{pcap.name}.meta.json").write_text(json.dumps(meta), encoding="utf-8")


def test_build_dataset_keeps_scenarios_in_one_split(tmp_path):
    raw_dir = tmp_path / "raw"
    output_dir = tmp_path / "processed"
    raw_dir.mkdir()
    for index, traffic_type in enumerate(("icmp", "tcp", "udp"), start=1):
        _write_capture(raw_dir, f"scen_{index:02d}_example", traffic_type)

    manifest = build_dataset(raw_dir, output_dir, seed=7)
    report = validate_manifest(manifest)

    assert report.valid
    assert {record.split for record in manifest.records} == {"train", "validation", "test"}
    assert len({record.scenario_id for record in manifest.records}) == 3
    assert (output_dir / "train.jsonl").is_file()
    assert (output_dir / "validation.jsonl").is_file()
    assert (output_dir / "test.jsonl").is_file()


def test_combined_traffic_capture_is_rejected(tmp_path):
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    pcap = raw_dir / "combined.pcap"
    wrpcap(str(pcap), [IP(proto=50) / ESP(spi=1, seq=1) / Raw(load=b"encrypted")])
    (raw_dir / "combined.pcap.meta.json").write_text(
        json.dumps({"scenario_id": "scen_01_example", "labels": {"traffic_types": ["icmp", "tcp"]}}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="exactly one traffic_type"):
        load_capture_record(pcap)


def test_validator_detects_scenario_leakage():
    records = [
        DatasetRecord(
            capture_id="capture-a",
            scenario_id="scenario-a",
            pcap_file="a.pcap",
            traffic_type="icmp",
            vpn_configuration={},
            protocol_metadata={},
            flow_features={},
            labels={"traffic_type": "icmp"},
            split="train",
        ),
        DatasetRecord(
            capture_id="capture-b",
            scenario_id="scenario-a",
            pcap_file="b.pcap",
            traffic_type="tcp",
            vpn_configuration={},
            protocol_metadata={},
            flow_features={},
            labels={"traffic_type": "tcp"},
            split="test",
        ),
    ]
    report = validate_manifest(DatasetManifest(split_seed=1, split_ratios={"train": 0.7, "validation": 0.15, "test": 0.15}, records=records))
    assert not report.valid
    assert any("scenario group scenario-a appears in multiple splits" in error for error in report.errors)
