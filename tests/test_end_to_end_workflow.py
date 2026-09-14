from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient
from scapy.all import ESP, IP, Raw, UDP, wrpcap

from backend.app import create_app
from backend.schemas import CompleteAnalysisResponse
from dataset.models import DatasetManifest
from dataset.pipeline import load_capture_record
from ml_classifier.pipeline import predict_flow_features, train_classifier
from packet_engine.analyzer import analyze_pcap
from reporting import generate_reports


def _write_pcap(path: Path, packet_count: int, payload_size: int) -> None:
    packets = [IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=500, dport=500) / Raw(load=b"ike")]
    packets.extend(
        IP(src="10.0.0.1", dst="10.0.0.2", proto=50) / ESP(spi=7, seq=index) / Raw(load=b"x" * payload_size)
        for index in range(1, packet_count + 1)
    )
    wrpcap(str(path), packets)


def _write_labeled_capture(raw_dir: Path, scenario_id: str, traffic_type: str, packet_count: int, payload_size: int, split: str):
    pcap_path = raw_dir / f"{scenario_id}.pcap"
    _write_pcap(pcap_path, packet_count, payload_size)
    metadata = {
        "scenario_id": scenario_id,
        "capture_id": scenario_id,
        "traffic_type": traffic_type,
        "labels": {
            "ipsec_mode": "tunnel",
            "ike_version": 2,
            "encryption": "aes256gcm16",
            "integrity": None,
            "prf": "sha256",
            "dh_group": "ecp384",
            "pfs_enabled": True,
            "ip_version": 4,
            "auth_method": "cert",
            "traffic_types": [traffic_type],
        },
    }
    (raw_dir / f"{pcap_path.name}.meta.json").write_text(json.dumps(metadata), encoding="utf-8")
    return load_capture_record(pcap_path).model_copy(update={"split": split})


def _secure_configuration() -> dict:
    return {
        "ipsec_mode": "tunnel",
        "ike_version": 2,
        "encryption": "aes256gcm16",
        "integrity": None,
        "prf": "sha256",
        "dh_group": "ecp384",
        "pfs_enabled": True,
        "ip_version": 4,
        "auth_method": "cert",
        "key_lifetime_seconds": 1800,
        "replay_protection": True,
    }


def _weak_configuration() -> dict:
    return {
        "ipsec_mode": "tunnel",
        "ike_version": 2,
        "encryption": "aes128cbc",
        "integrity": "sha1",
        "prf": "sha1",
        "dh_group": "modp2048",
        "pfs_enabled": False,
        "ip_version": 4,
        "auth_method": "psk",
        "key_lifetime_seconds": 7200,
        "replay_protection": False,
    }


def test_secure_and_weak_workflows_match_all_component_outputs(tmp_path):
    raw_dir = tmp_path / "training-captures"
    raw_dir.mkdir()
    records = [
        _write_labeled_capture(raw_dir, "train-icmp", "icmp", 3, 20, "train"),
        _write_labeled_capture(raw_dir, "train-tcp", "tcp", 5, 80, "train"),
        _write_labeled_capture(raw_dir, "train-udp", "udp", 7, 140, "train"),
        _write_labeled_capture(raw_dir, "train-iperf", "iperf", 9, 220, "train"),
        _write_labeled_capture(raw_dir, "validation-tcp", "tcp", 6, 90, "validation"),
        _write_labeled_capture(raw_dir, "test-udp", "udp", 8, 150, "test"),
    ]
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(DatasetManifest(split_seed=1, split_ratios={"train": 0.7, "validation": 0.15, "test": 0.15}, records=records).model_dump()), encoding="utf-8")
    model_path = tmp_path / "model.joblib"
    bundle = train_classifier(manifest_path, model_path, seed=4)

    app = create_app(tmp_path / "uploads", model_path=model_path)
    client = TestClient(app)
    secure_pcap = raw_dir / "train-tcp.pcap"
    weak_pcap = raw_dir / "train-udp.pcap"
    secure_upload = client.post("/api/v1/captures", files={"file": ("secure.pcap", secure_pcap.read_bytes(), "application/vnd.tcpdump.pcap")})
    weak_upload = client.post("/api/v1/captures", files={"file": ("weak.pcap", weak_pcap.read_bytes(), "application/vnd.tcpdump.pcap")})
    assert secure_upload.status_code == 201
    assert weak_upload.status_code == 201

    responses = []
    for capture_id, configuration in ((secure_upload.json()["capture_id"], _secure_configuration()), (weak_upload.json()["capture_id"], _weak_configuration())):
        response = client.post(f"/api/v1/captures/{capture_id}/analyze", json={"vpn_configuration": configuration})
        assert response.status_code == 200
        parsed = CompleteAnalysisResponse.model_validate(response.json())
        responses.append(parsed)

    secure_result, weak_result = responses
    assert secure_result.packet_analysis.packet_summary.packet_count.value == analyze_pcap(secure_pcap).packet_summary.packet_count.value
    assert secure_result.prediction.confidence.status == "inferred"
    flattened_features = {
        name: value.get("value") if isinstance(value, dict) else value
        for name, value in secure_result.features.derived_flow_features.model_dump().items()
    }
    direct_prediction = predict_flow_features(bundle, flattened_features)
    assert secure_result.prediction.predicted_traffic_type.value == direct_prediction.predicted_traffic_type
    assert secure_result.prediction.confidence.value == direct_prediction.confidence
    assert secure_result.risk_assessment.overall_score is not None
    assert weak_result.risk_assessment.overall_score is not None
    assert weak_result.risk_assessment.overall_score < secure_result.risk_assessment.overall_score
    assert any(finding.evidence for finding in weak_result.security_assessment.findings)
    assert next(finding for finding in weak_result.security_assessment.findings if finding.rule_id == "pfs").severity == "medium"
    assert next(finding for finding in weak_result.security_assessment.findings if finding.rule_id == "replay-protection").severity == "high"

    secure_reports = generate_reports(secure_result)
    weak_reports = generate_reports(weak_result)
    assert str(secure_result.risk_assessment.overall_score) in secure_reports.executive.markdown
    assert str(weak_result.risk_assessment.overall_score) in weak_reports.technical.markdown
    assert "encrypted payload contents" in secure_reports.technical.markdown.lower()


def test_workflow_preserves_unavailable_configuration(tmp_path):
    raw_dir = tmp_path / "captures"
    raw_dir.mkdir()
    pcap_path = raw_dir / "capture.pcap"
    _write_pcap(pcap_path, 2, 32)
    app = create_app(tmp_path / "uploads")
    client = TestClient(app)
    upload = client.post("/api/v1/captures", files={"file": ("capture.pcap", pcap_path.read_bytes(), "application/octet-stream")})

    response = client.post(f"/api/v1/captures/{upload.json()['capture_id']}/analyze", json={"vpn_configuration": {}})
    result = CompleteAnalysisResponse.model_validate(response.json())

    assert result.risk_assessment.score_status == "partial"
    assert result.risk_assessment.overall_score is not None
    assert any(finding.status == "unavailable" for finding in result.security_assessment.findings)
    report = generate_reports(result).technical.markdown
    assert "Unavailable" in report
