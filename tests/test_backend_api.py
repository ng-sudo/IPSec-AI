from __future__ import annotations

from pathlib import Path

import numpy as np
from fastapi.testclient import TestClient
from scapy.all import ESP, IP, Raw, UDP, wrpcap
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline

from backend.app import create_app
from ml_classifier.pipeline import ClassifierBundle, save_bundle


def _pcap_bytes(tmp_path: Path) -> bytes:
    source = tmp_path / "api-sample.pcap"
    wrpcap(
        str(source),
        [
            IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=500, dport=500) / Raw(load=b"ike"),
            IP(src="10.0.0.1", dst="10.0.0.2", proto=50) / ESP(spi=1, seq=1) / Raw(load=b"encrypted"),
        ],
    )
    return source.read_bytes()


def _vpn_configuration() -> dict:
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
    }


def test_health_openapi_and_capture_selection(tmp_path):
    client = TestClient(create_app(tmp_path / "uploads"))

    health = client.get("/health")
    assert health.status_code == 200
    assert health.json() == {"status": "ok", "classifier_available": False}

    upload = client.post(
        "/api/v1/captures",
        files={"file": ("sample.pcap", _pcap_bytes(tmp_path), "application/vnd.tcpdump.pcap")},
    )
    assert upload.status_code == 201
    capture_id = upload.json()["capture_id"]

    captures = client.get("/api/v1/captures")
    assert captures.status_code == 200
    assert captures.json()[0]["capture_id"] == capture_id
    assert "/api/v1/captures" in client.get("/openapi.json").json()["paths"]


def test_analysis_returns_all_layered_results_and_unavailable_prediction(tmp_path):
    client = TestClient(create_app(tmp_path / "uploads"))
    upload = client.post("/api/v1/captures", files={"file": ("sample.pcap", _pcap_bytes(tmp_path), "application/octet-stream")})
    capture_id = upload.json()["capture_id"]

    response = client.post(
        f"/api/v1/captures/{capture_id}/analyze",
        json={"vpn_configuration": _vpn_configuration()},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["capture_id"] == capture_id
    assert body["packet_analysis"]["ipsec_detected"]["status"] == "observed"
    assert body["features"]["derived_flow_features"]["packet_count"]["status"] == "observed"
    assert body["prediction"]["predicted_traffic_type"]["status"] == "unavailable"
    assert body["prediction"]["confidence"]["status"] == "unavailable"
    assert body["metadata_inference"]["encrypted_payload_contents"]["status"] == "unavailable"
    assert len(body["security_assessment"]["findings"]) == 10
    assert len(body["risk_assessment"]["threat_risk_matrix"]) == 7
    assert body["risk_assessment"]["evidence"]


def test_analysis_uses_configured_classifier_and_returns_confidence(tmp_path):
    model_path = tmp_path / "classifier.joblib"
    pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("classifier", RandomForestClassifier(n_estimators=20, random_state=1)),
    ])
    pipeline.fit(np.asarray([[1.0, 40.0], [100.0, 4000.0]]), ["icmp", "tcp"])
    save_bundle(ClassifierBundle(
        model_version="test-model/1",
        model_name="random_forest",
        feature_names=["packet_count", "byte_count"],
        classes=["icmp", "tcp"],
        pipeline=pipeline,
        validation_metrics={},
        test_metrics={},
        training_metadata={},
    ), model_path)
    client = TestClient(create_app(tmp_path / "uploads", model_path=model_path))
    upload = client.post("/api/v1/captures", files={"file": ("sample.pcap", _pcap_bytes(tmp_path), "application/octet-stream")})

    response = client.post(
        f"/api/v1/captures/{upload.json()['capture_id']}/analyze",
        json={"vpn_configuration": _vpn_configuration()},
    )

    assert response.status_code == 200
    prediction = response.json()["prediction"]
    assert prediction["predicted_traffic_type"]["status"] == "inferred"
    assert prediction["predicted_traffic_type"]["value"] in {"icmp", "tcp"}
    assert prediction["confidence"]["status"] == "inferred"
    assert prediction["model_version"]["value"] == "test-model/1"


def test_upload_validation_and_missing_capture_errors(tmp_path):
    client = TestClient(create_app(tmp_path / "uploads"))

    invalid = client.post("/api/v1/captures", files={"file": ("notes.txt", b"not a pcap", "text/plain")})
    assert invalid.status_code == 400
    assert "supported" in invalid.json()["detail"]

    missing = client.post(
        "/api/v1/captures/not-found/analyze",
        json={"vpn_configuration": {}},
    )
    assert missing.status_code == 404
