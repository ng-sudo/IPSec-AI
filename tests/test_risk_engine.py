from __future__ import annotations

from security_engine import AssessmentContext, SecurityAssessmentEngine
from security_engine.models import AssessmentFinding
from risk_engine import RiskScoringEngine, ScoringConfig


def _complete_context() -> AssessmentContext:
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
        flow_features={"source_destination_summary": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}},
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


def test_secure_configuration_gets_complete_high_score():
    findings = SecurityAssessmentEngine().assess(_complete_context())
    result = RiskScoringEngine().score(findings)

    assert result.overall_score == 98.5
    assert result.score_status == "complete"
    assert result.risk_level == "info"
    assert result.known_weight == 1.0
    assert len(result.category_scores) == 7
    assert len(result.threat_risk_matrix) == 7
    assert all(category.evidence for category in result.category_scores)


def test_weak_configuration_gets_low_score_and_traceable_matrix():
    findings = SecurityAssessmentEngine().assess(_weak_context())
    result = RiskScoringEngine().score(findings)

    assert result.overall_score < 60
    assert result.risk_level == "moderate"
    assert result.score_status == "complete"
    sa_entry = next(entry for entry in result.threat_risk_matrix if entry.category == "sa_security")
    assert sa_entry.likelihood == 4
    assert sa_entry.impact == 4
    assert sa_entry.evidence


def test_mixed_findings_use_configured_weights():
    findings = [
        AssessmentFinding(rule_id="crypto", category="cryptographic_strength", severity="info", title="ok", evidence="cipher observed", explanation="known", recommendation="keep", status="observed"),
        AssessmentFinding(rule_id="config", category="configuration_compliance", severity="high", title="bad", evidence="ike v1", explanation="weak", recommendation="upgrade", status="observed"),
        AssessmentFinding(rule_id="sa-parameters", category="sa_parameters", severity="medium", title="mixed", evidence="sa partial", explanation="known", recommendation="verify", status="observed"),
        AssessmentFinding(rule_id="lifetime", category="key_lifetime", severity="info", title="unknown", evidence="missing", explanation="unknown", recommendation="measure", status="unavailable"),
        AssessmentFinding(rule_id="replay", category="replay_protection", severity="info", title="ok", evidence="enabled", explanation="known", recommendation="keep", status="observed"),
        AssessmentFinding(rule_id="pfs", category="pfs", severity="info", title="ok", evidence="enabled", explanation="known", recommendation="keep", status="observed"),
        AssessmentFinding(rule_id="metadata", category="metadata_exposure", severity="low", title="visible", evidence="endpoint", explanation="known", recommendation="review", status="observed"),
    ]
    result = RiskScoringEngine().score_findings(findings)

    assert result.score_status == "partial"
    assert result.risk_level == "insufficient_data"
    assert result.overall_score == 74.71
    assert result.known_weight == 0.85
    lifetime = next(category for category in result.category_scores if category.category == "key_management")
    assert lifetime.score is None
    assert lifetime.status == "unavailable"


def test_unavailable_findings_never_become_secure():
    findings = SecurityAssessmentEngine().assess(AssessmentContext())
    result = RiskScoringEngine().score(findings)

    assert result.score_status == "unavailable"
    assert result.overall_score is None
    assert result.risk_level == "insufficient_data"
    assert all(category.score is None for category in result.category_scores)
    assert all(entry.risk_level == "insufficient_data" for entry in result.threat_risk_matrix)


def test_weights_are_configurable_and_must_sum_to_one():
    config = ScoringConfig(weights={
        "cryptographic_strength": 0.10,
        "configuration_compliance": 0.20,
        "sa_security": 0.15,
        "key_management": 0.20,
        "replay_protection": 0.10,
        "pfs": 0.10,
        "metadata_exposure": 0.15,
    })
    result = RiskScoringEngine(config).score(SecurityAssessmentEngine().assess(_complete_context()))
    assert next(category for category in result.category_scores if category.category == "cryptographic_strength").weight == 0.1
