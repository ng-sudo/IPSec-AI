from __future__ import annotations

import json

from reporting import generate_executive_report, generate_reports, generate_technical_report, write_reports


def _analysis_result() -> dict:
    return {
        "capture_id": "capture-controlled-1",
        "vpn_configuration": {
            "ipsec_mode": "tunnel",
            "encryption": "aes256gcm16",
            "integrity": None,
            "prf": "sha256",
            "auth_method": "cert",
            "dh_group": "ecp384",
            "ip_version": 4,
            "pfs_enabled": True,
            "replay_protection": None,
            "key_lifetime_seconds": None,
        },
        "packet_analysis": {
            "ipsec_protocols": {"status": "observed", "value": ["esp"]},
            "packet_summary": {
                "packet_count": {"status": "observed", "value": 12},
                "byte_count": {"status": "observed", "value": 1440},
                "duration_seconds": {"status": "observed", "value": 3.5},
            },
        },
        "features": {
            "derived_flow_features": {
                "packet_size_mean": {"status": "observed", "value": 120.0},
                "inter_arrival_mean": {"status": "inferred", "value": 0.31},
                "packets_per_second": {"status": "observed", "value": 3.42},
                "bytes_per_second": {"status": "observed", "value": 411.4},
                "esp_packet_ratio": {"status": "observed", "value": 1.0},
            }
        },
        "prediction": {
            "predicted_traffic_type": {"status": "inferred", "value": "tcp"},
            "confidence": {"status": "inferred", "value": 0.91},
            "model_version": {"status": "observed", "value": "test-model/1"},
        },
        "metadata_inference": {
            "ipsec_detected": {"status": "observed", "value": True},
            "ike_version": {"status": "observed", "value": 2},
            "source_ip": {"status": "observed", "value": "10.0.0.1"},
            "destination_ip": {"status": "observed", "value": "10.0.0.2"},
            "flow_direction": {"status": "inferred", "value": "forward"},
            "encrypted_payload_contents": {"status": "unavailable", "value": None, "notes": "not inspected"},
        },
        "security_assessment": {
            "findings": [
                {
                    "rule_id": "replay-protection",
                    "category": "replay_protection",
                    "severity": "info",
                    "title": "Replay protection unavailable",
                    "evidence": "replay_protection was not observed",
                    "explanation": "The result does not expose this parameter.",
                    "recommendation": "Provide negotiated replay metadata.",
                    "status": "unavailable",
                },
                {
                    "rule_id": "cipher-strength",
                    "category": "cipher_strength",
                    "severity": "info",
                    "title": "AES-256 cipher observed",
                    "evidence": "encryption=aes256gcm16",
                    "explanation": "AES-256-GCM was supplied.",
                    "recommendation": "Continue using approved ciphers.",
                    "status": "observed",
                },
            ]
        },
        "risk_assessment": {
            "overall_score": 86.5,
            "risk_level": "low",
            "score_status": "partial",
            "known_weight": 0.85,
            "category_scores": [],
            "threat_risk_matrix": [{"category": "replay_protection", "security_score": None, "risk_level": "insufficient_data", "likelihood": None, "impact": 4, "status": "unavailable", "evidence": []}],
            "evidence": ["replay-protection unavailable"],
        },
    }


def test_executive_report_uses_actual_summary_and_preserves_unavailable():
    report = generate_executive_report(_analysis_result())

    assert report.report_type == "executive"
    assert report.capture_id == "capture-controlled-1"
    assert "86.5" in report.markdown
    assert "tcp" in report.markdown
    assert "Unavailable" in report.markdown
    assert "observed" in report.markdown
    assert "inferred" in report.markdown
    assert "unavailable" in report.markdown
    assert any(section.title == "Recommendations" for section in report.sections)


def test_technical_report_contains_required_analysis_sections_and_evidence():
    report = generate_technical_report(_analysis_result())
    titles = {section.title for section in report.sections}

    assert {
        "IPsec / IKE identification",
        "VPN configuration",
        "Traffic analysis",
        "AI traffic classification",
        "Security findings",
        "Cryptographic assessment",
        "Security controls",
        "Security and risk score",
        "Threat / risk matrix",
        "Recommendations",
    }.issubset(titles)
    assert "replay_protection was not observed" in report.markdown
    assert "Provide negotiated replay metadata." in report.markdown


def test_report_bundle_and_file_output_are_reusable(tmp_path):
    bundle = generate_reports(_analysis_result())
    output = write_reports(_analysis_result(), tmp_path / "reports")

    assert bundle.executive.markdown
    assert output.technical.markdown
    assert (tmp_path / "reports" / "executive.md").is_file()
    assert (tmp_path / "reports" / "technical.md").is_file()
    persisted = json.loads((tmp_path / "reports" / "reports.json").read_text(encoding="utf-8"))
    assert persisted["executive"]["capture_id"] == "capture-controlled-1"
