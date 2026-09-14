from __future__ import annotations

from dataset.models import DatasetRecord
from security_engine import (
    AssessmentContext,
    AssessmentFinding,
    AssessmentRule,
    SecurityAssessmentEngine,
    SecurityRuleConfig,
)


def _secure_context() -> AssessmentContext:
    return AssessmentContext.from_mappings(
        vpn_configuration={
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
        },
        protocol_metadata={"ipsec_detected": True, "ike_detected": True, "esp_packets": 100},
        flow_features={"source_destination_summary": {"src_ip": None, "dst_ip": None}},
    )


def _weak_context() -> AssessmentContext:
    return AssessmentContext.from_mappings(
        vpn_configuration={
            "ipsec_mode": "transport",
            "ike_version": 1,
            "encryption": "aes128cbc",
            "integrity": "sha1",
            "prf": "sha1",
            "dh_group": "modp2048",
            "pfs_enabled": False,
            "ip_version": 4,
            "auth_method": "psk",
            "key_lifetime_seconds": 7200,
            "replay_protection": False,
        },
        protocol_metadata={"ipsec_detected": False, "ike_detected": True, "esp_packets": 0},
        flow_features={"source_destination_summary": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}},
    )


def test_secure_configuration_produces_complete_observed_findings():
    assessment = SecurityAssessmentEngine().assess(_secure_context())

    assert assessment.summary.finding_count == 10
    assert all(finding.status in {"observed", "inferred", "unavailable"} for finding in assessment.findings)
    assert not any(finding.severity in {"high", "critical"} for finding in assessment.findings)
    assert next(f for f in assessment.findings if f.rule_id == "pfs").status == "observed"
    assert next(f for f in assessment.findings if f.rule_id == "key-lifetime").severity == "info"


def test_weak_configuration_reports_actionable_findings():
    assessment = SecurityAssessmentEngine().assess(_weak_context())
    findings = {finding.rule_id: finding for finding in assessment.findings}

    assert findings["crypto-strength"].severity == "high"
    assert findings["pfs"].severity == "medium"
    assert findings["replay-protection"].severity == "high"
    assert findings["key-lifetime"].severity == "medium"
    assert findings["sa-parameters"].severity == "high"
    assert findings["metadata-exposure"].status == "observed"
    for finding in assessment.findings:
        assert finding.evidence
        assert finding.explanation
        assert finding.recommendation


def test_missing_configuration_is_explicitly_unavailable():
    assessment = SecurityAssessmentEngine().assess(AssessmentContext())
    findings = {finding.rule_id: finding for finding in assessment.findings}

    assert findings["key-lifetime"].status == "unavailable"
    assert findings["replay-protection"].status == "unavailable"
    assert findings["pfs"].status == "unavailable"
    assert findings["authentication"].status == "unavailable"
    assert findings["dh-strength"].status == "unavailable"
    assert findings["metadata-exposure"].status == "unavailable"
    assert "not present" in findings["key-lifetime"].evidence


def test_custom_rule_and_threshold_are_supported():
    def custom_rule(context: AssessmentContext, config: SecurityRuleConfig) -> AssessmentFinding:
        return AssessmentFinding(
            rule_id="custom",
            category="custom",
            severity="info",
            title="Custom rule ran",
            evidence="test evidence",
            explanation="test explanation",
            recommendation="test recommendation",
            status="inferred",
        )

    engine = SecurityAssessmentEngine(
        rules=[AssessmentRule("custom", "custom", custom_rule)],
        config=SecurityRuleConfig(max_key_lifetime_seconds=900),
    )
    result = engine.assess(AssessmentContext())
    assert result.findings[0].rule_id == "custom"
    assert result.findings[0].status == "inferred"


def test_dataset_record_adapter_preserves_observation_status():
    record = DatasetRecord(
        capture_id="capture-1",
        scenario_id="scenario-1",
        pcap_file="capture-1.pcap",
        traffic_type="tcp",
        vpn_configuration={"pfs_enabled": {"status": "observed", "value": True}},
        protocol_metadata={"ipsec_detected": {"status": "observed", "value": True}},
        flow_features={},
        labels={"traffic_type": "tcp"},
    )

    assessment = SecurityAssessmentEngine().assess_record(record)
    findings = {finding.rule_id: finding for finding in assessment.findings}
    assert findings["pfs"].status == "observed"
    assert findings["sa-parameters"].status == "observed"
