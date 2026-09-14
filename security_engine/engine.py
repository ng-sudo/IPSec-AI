from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Mapping, Sequence

from dataset.models import DatasetRecord

from .models import (
    AssessmentContext,
    AssessmentFinding,
    AssessmentSummary,
    SecurityAssessment,
    SecurityRuleConfig,
    Severity,
    Status,
)

RuleEvaluator = Callable[[AssessmentContext, SecurityRuleConfig], AssessmentFinding]


@dataclass(frozen=True)
class AssessmentRule:
    rule_id: str
    category: str
    evaluate: RuleEvaluator


def _read(mapping: Mapping[str, Any], key: str) -> tuple[Any, Status]:
    if key not in mapping:
        return None, "unavailable"
    raw = mapping[key]
    if isinstance(raw, Mapping) and "status" in raw and "value" in raw:
        status = raw.get("status")
        if status in {"observed", "inferred", "unavailable"}:
            return raw.get("value"), status
        return raw.get("value"), "unavailable"
    if raw is None:
        return None, "unavailable"
    return raw, "observed"


def _read_any(context: AssessmentContext, keys: Sequence[str]) -> tuple[Any, Status, str]:
    for source_name, source in (
        ("vpn_configuration", context.vpn_configuration),
        ("protocol_metadata", context.protocol_metadata),
        ("flow_features", context.flow_features),
    ):
        for key in keys:
            value, status = _read(source, key)
            if status != "unavailable":
                return value, status, f"{source_name}.{key}"
    return None, "unavailable", keys[0]


def _finding(
    rule_id: str,
    category: str,
    severity: Severity,
    title: str,
    evidence: str,
    explanation: str,
    recommendation: str,
    status: Status,
    observed_value: Any = None,
) -> AssessmentFinding:
    return AssessmentFinding(
        rule_id=rule_id,
        category=category,
        severity=severity,
        title=title,
        evidence=evidence,
        explanation=explanation,
        recommendation=recommendation,
        status=status,
        observed_value=observed_value,
    )


def _unavailable(rule_id: str, category: str, title: str, field: str, recommendation: str) -> AssessmentFinding:
    return _finding(
        rule_id, category, "info", title,
        f"{field} was not present as an observed or inferred value.",
        "The available configuration and protocol metadata do not expose this parameter, so no security conclusion is made.",
        recommendation,
        "unavailable",
    )


def _cryptographic_strength(context: AssessmentContext, config: SecurityRuleConfig) -> AssessmentFinding:
    integrity, integrity_status, integrity_source = _read_any(context, ("integrity",))
    prf, prf_status, prf_source = _read_any(context, ("prf",))
    if integrity_status == "unavailable" and prf_status == "unavailable":
        return _unavailable("crypto-strength", "cryptographic_strength", "Integrity strength unavailable", "integrity/prf", "Provide the negotiated integrity and PRF algorithms.")
    weak = {"sha1"}
    weak_fields = [f"{source}={value}" for source, value, status in ((integrity_source, integrity, integrity_status), (prf_source, prf, prf_status)) if status != "unavailable" and value in weak]
    if weak_fields:
        return _finding("crypto-strength", "cryptographic_strength", "high", "Legacy hash algorithm observed", "; ".join(weak_fields), "SHA-1 is a legacy integrity or PRF algorithm and is not appropriate for a modern VPN policy.", "Use SHA-256 or stronger integrity and PRF algorithms.", "observed", weak_fields)
    values = {str(value) for value, status in ((integrity, integrity_status), (prf, prf_status)) if status != "unavailable"}
    return _finding("crypto-strength", "cryptographic_strength", "info", "Modern integrity configuration observed", f"integrity={integrity!r}, prf={prf!r}", "No configured integrity or PRF value matched the legacy algorithms known to this rule set.", "Continue enforcing approved integrity and PRF algorithms.", "observed" if integrity_status == "observed" or prf_status == "observed" else "inferred", sorted(values))


def _cipher_strength(context: AssessmentContext, config: SecurityRuleConfig) -> AssessmentFinding:
    cipher, status, source = _read_any(context, ("encryption", "cipher"))
    if status == "unavailable":
        return _unavailable("cipher-strength", "cipher_strength", "Cipher strength unavailable", "encryption", "Provide the configured or negotiated ESP cipher.")
    cipher_text = str(cipher).lower()
    if cipher_text in {"aes128cbc", "aes128gcm16"}:
        severity: Severity = "medium" if cipher_text == "aes128cbc" else "low"
        explanation = "AES-128 is a recognized cipher strength, but AES-256 is preferred for a higher security margin." if cipher_text == "aes128cbc" else "AES-128-GCM provides authenticated encryption but has a smaller key size than AES-256-GCM."
        return _finding("cipher-strength", "cipher_strength", severity, "AES-128 cipher observed", f"{source}={cipher}", explanation, "Prefer AES-256-GCM where both peers support it.", status, cipher)
    if cipher_text in {"aes256cbc", "aes256gcm16"}:
        return _finding("cipher-strength", "cipher_strength", "info", "AES-256 cipher observed", f"{source}={cipher}", "The configured cipher provides a 256-bit AES key; GCM also provides authenticated encryption.", "Keep the cipher in the approved policy set and prefer AES-GCM when compatible.", status, cipher)
    return _finding("cipher-strength", "cipher_strength", "medium", "Unrecognized cipher requires review", f"{source}={cipher}", "The rule set cannot establish the strength of this cipher identifier.", "Verify the cipher against the approved VPN cryptographic policy.", status, cipher)


def _configuration_compliance(context: AssessmentContext, config: SecurityRuleConfig) -> AssessmentFinding:
    required = ("ipsec_mode", "ike_version", "encryption", "dh_group", "ip_version", "auth_method")
    missing = [key for key in required if _read(context.vpn_configuration, key)[1] == "unavailable"]
    if missing:
        return _unavailable("configuration-compliance", "configuration_compliance", "Configuration compliance is incomplete", ", ".join(missing), "Provide the missing VPN configuration fields before assessing compliance.")
    issues: List[str] = []
    ike_version = context.vpn_configuration["ike_version"]
    if ike_version not in config.accepted_ike_versions:
        issues.append(f"ike_version={ike_version!r} is outside the accepted set")
    mode = context.vpn_configuration["ipsec_mode"]
    if mode not in {"tunnel", "transport"}:
        issues.append(f"ipsec_mode={mode!r} is not recognized")
    encryption = str(context.vpn_configuration["encryption"])
    integrity = context.vpn_configuration.get("integrity")
    if "gcm" in encryption and integrity is not None:
        issues.append("AEAD GCM is configured with a separate integrity value")
    if "cbc" in encryption and integrity is None:
        issues.append("CBC is configured without an integrity value")
    if issues:
        return _finding("configuration-compliance", "configuration_compliance", "high", "VPN configuration violates policy checks", "; ".join(issues), "One or more supplied configuration values conflict with the configured compliance rules.", "Correct the listed configuration conflicts and re-establish the Security Association.", "observed", issues)
    return _finding("configuration-compliance", "configuration_compliance", "info", "VPN configuration passes available policy checks", "Required configuration fields were observed and passed the configured checks.", "The engine only evaluated fields supplied by the configuration input; it did not assume values for omitted settings.", "Continue validating the complete negotiated configuration against organizational policy.", "observed")


def _sa_parameters(context: AssessmentContext, config: SecurityRuleConfig) -> AssessmentFinding:
    value, status, source = _read_any(context, ("ipsec_detected", "esp_packets", "ike_detected"))
    if status == "unavailable":
        return _unavailable("sa-parameters", "sa_parameters", "Security Association parameters unavailable", "ipsec_detected/esp_packets/ike_detected", "Capture IKE and ESP metadata or provide negotiated SA parameters.")
    if value is False or value == 0:
        return _finding("sa-parameters", "sa_parameters", "high", "Expected IPsec SA evidence was not observed", f"{source}={value!r}", "The available protocol metadata does not show the expected IPsec/ESP evidence.", "Verify tunnel establishment and capture the negotiated SA traffic.", status, value)
    return _finding("sa-parameters", "sa_parameters", "info", "IPsec SA evidence observed", f"{source}={value!r}", "IPsec-related protocol evidence is present in the supplied observation set.", "Retain the capture and negotiated SA metadata for complete review.", status, value)


def _key_lifetime(context: AssessmentContext, config: SecurityRuleConfig) -> AssessmentFinding:
    value, status, source = _read_any(context, ("key_lifetime_seconds", "key_lifetime"))
    if status == "unavailable":
        return _unavailable("key-lifetime", "key_lifetime", "Key lifetime unavailable", "key_lifetime_seconds", "Provide negotiated or configured key lifetime metadata.")
    try:
        lifetime = float(value)
    except (TypeError, ValueError):
        return _finding("key-lifetime", "key_lifetime", "medium", "Key lifetime value requires review", f"{source}={value!r}", "The supplied lifetime is not numeric, so the configured threshold cannot be applied.", "Supply key lifetime in seconds and compare it with the approved policy.", status, value)
    if lifetime > config.max_key_lifetime_seconds:
        return _finding("key-lifetime", "key_lifetime", "medium", "Key lifetime exceeds configured maximum", f"{source}={lifetime:g}s", "Longer key lifetimes increase the amount of traffic protected by one key.", "Reduce the key lifetime to the configured maximum or an approved policy value.", status, lifetime)
    return _finding("key-lifetime", "key_lifetime", "info", "Key lifetime is within configured maximum", f"{source}={lifetime:g}s", "The observed key lifetime does not exceed the configured threshold.", "Continue monitoring rekey behavior.", status, lifetime)


def _replay_protection(context: AssessmentContext, config: SecurityRuleConfig) -> AssessmentFinding:
    value, status, source = _read_any(context, ("replay_protection", "replay_enabled", "replay_window"))
    if status == "unavailable":
        return _unavailable("replay-protection", "replay_protection", "Replay protection unavailable", "replay_protection", "Provide negotiated replay protection or replay-window metadata.")
    if value is False or value == 0:
        return _finding("replay-protection", "replay_protection", "high", "Replay protection is disabled", f"{source}={value!r}", "The supplied configuration explicitly disables replay protection.", "Enable replay protection and verify the negotiated replay window.", status, value)
    return _finding("replay-protection", "replay_protection", "info", "Replay protection is enabled or configured", f"{source}={value!r}", "The supplied metadata indicates replay protection is enabled or a replay window is configured.", "Keep replay protection enabled and monitor SA behavior.", status, value)


def _pfs(context: AssessmentContext, config: SecurityRuleConfig) -> AssessmentFinding:
    value, status, source = _read_any(context, ("pfs_enabled", "pfs"))
    if status == "unavailable":
        return _unavailable("pfs", "pfs", "Perfect Forward Secrecy unavailable", "pfs_enabled", "Provide the configured or negotiated PFS setting.")
    if value is False:
        return _finding("pfs", "pfs", "medium", "Perfect Forward Secrecy is disabled", f"{source}={value!r}", "Without PFS, a later compromise of keying material can expose more Child SA traffic.", "Enable PFS with an approved DH group.", status, value)
    return _finding("pfs", "pfs", "info", "Perfect Forward Secrecy is enabled", f"{source}={value!r}", "The supplied configuration indicates Child SA rekeying uses PFS.", "Keep PFS enabled for approved Child SA configurations.", status, value)


def _authentication(context: AssessmentContext, config: SecurityRuleConfig) -> AssessmentFinding:
    value, status, source = _read_any(context, ("auth_method", "authentication"))
    if status == "unavailable":
        return _unavailable("authentication", "authentication_configuration", "Authentication configuration unavailable", "auth_method", "Provide the IKE authentication method.")
    if value == "psk":
        return _finding("authentication", "authentication_configuration", "medium", "Pre-shared key authentication observed", f"{source}={value!r}", "PSK authentication can be appropriate in a controlled testbed, but its security depends on secret generation, distribution, and rotation.", "Use managed certificates or enforce strong, rotated PSKs according to policy.", status, value)
    if value == "cert":
        return _finding("authentication", "authentication_configuration", "info", "Certificate authentication observed", f"{source}={value!r}", "Certificate-based IKE authentication is present in the supplied configuration.", "Continue validating certificate trust, expiry, and revocation policy.", status, value)
    return _finding("authentication", "authentication_configuration", "medium", "Authentication method requires review", f"{source}={value!r}", "The supplied authentication method is not in the configured accepted method list.", "Verify and replace it with an approved authentication method.", status, value)


def _dh_strength(context: AssessmentContext, config: SecurityRuleConfig) -> AssessmentFinding:
    value, status, source = _read_any(context, ("dh_group", "key_exchange"))
    if status == "unavailable":
        return _unavailable("dh-strength", "dh_key_exchange_strength", "DH/key-exchange strength unavailable", "dh_group", "Provide the negotiated or configured DH group.")
    strength = config.minimum_dh_strength.get(str(value))
    if strength == "strong":
        return _finding("dh-strength", "dh_key_exchange_strength", "info", "Approved strong DH group observed", f"{source}={value!r}", "The supplied DH group is marked strong by the active rule configuration.", "Continue using an approved DH group with PFS where required.", status, value)
    if strength == "medium":
        return _finding("dh-strength", "dh_key_exchange_strength", "low", "DH group provides moderate strength", f"{source}={value!r}", "The configured rule policy recognizes this DH group but assigns it a moderate strength classification.", "Prefer a stronger approved DH group when interoperability permits.", status, value)
    return _finding("dh-strength", "dh_key_exchange_strength", "medium", "DH group is not recognized by policy", f"{source}={value!r}", "The active rules do not establish the strength of this key-exchange group.", "Verify the group against the approved cryptographic policy.", status, value)


def _metadata_exposure(context: AssessmentContext, config: SecurityRuleConfig) -> AssessmentFinding:
    value, status, source = _read_any(context, ("source_destination_summary", "src_ip", "dst_ip", "metadata_exposure"))
    if status == "unavailable":
        return _unavailable("metadata-exposure", "metadata_exposure", "Metadata exposure unavailable", "endpoint metadata", "Provide observable endpoint metadata if exposure assessment is required.")
    if isinstance(value, Mapping) and not any(item not in (None, "") for item in value.values()):
        return _unavailable("metadata-exposure", "metadata_exposure", "Metadata exposure unavailable", source, "Provide observable endpoint metadata if exposure assessment is required.")
    return _finding("metadata-exposure", "metadata_exposure", "low", "Endpoint or flow metadata is observable", f"{source}={value!r}", "The supplied observation includes endpoint or flow metadata that remains visible to the observer even when ESP payload contents are encrypted.", "Minimize unnecessary endpoint exposure and document which outer metadata is expected to remain visible.", status, value)


DEFAULT_RULES: tuple[AssessmentRule, ...] = (
    AssessmentRule("crypto-strength", "cryptographic_strength", _cryptographic_strength),
    AssessmentRule("cipher-strength", "cipher_strength", _cipher_strength),
    AssessmentRule("configuration-compliance", "configuration_compliance", _configuration_compliance),
    AssessmentRule("sa-parameters", "sa_parameters", _sa_parameters),
    AssessmentRule("key-lifetime", "key_lifetime", _key_lifetime),
    AssessmentRule("replay-protection", "replay_protection", _replay_protection),
    AssessmentRule("pfs", "pfs", _pfs),
    AssessmentRule("authentication", "authentication_configuration", _authentication),
    AssessmentRule("dh-strength", "dh_key_exchange_strength", _dh_strength),
    AssessmentRule("metadata-exposure", "metadata_exposure", _metadata_exposure),
)


class SecurityAssessmentEngine:
    """Configurable deterministic assessment rule engine."""

    def __init__(self, rules: Sequence[AssessmentRule] = DEFAULT_RULES, config: SecurityRuleConfig | None = None):
        self.rules = tuple(rules)
        self.config = config or SecurityRuleConfig()

    def assess(self, context: AssessmentContext) -> SecurityAssessment:
        findings = [rule.evaluate(context, self.config) for rule in self.rules]
        severity_counts = Counter(finding.severity for finding in findings)
        status_counts = Counter(finding.status for finding in findings)
        return SecurityAssessment(
            findings=findings,
            summary=AssessmentSummary(
                finding_count=len(findings),
                severity_counts=dict(severity_counts),
                status_counts=dict(status_counts),
            ),
        )

    def assess_record(self, record: DatasetRecord) -> SecurityAssessment:
        return self.assess(AssessmentContext.from_mappings(record.vpn_configuration, record.protocol_metadata, record.flow_features))
