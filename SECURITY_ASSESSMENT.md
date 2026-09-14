# Deterministic IPsec Security Assessment

The `security_engine` package evaluates supplied VPN configuration and observed protocol metadata with explicit deterministic rules. It is separate from packet parsing and the ML classifier. It does not produce a security score, dashboard, or report.

## Usage

```python
from security_engine import AssessmentContext, SecurityAssessmentEngine

context = AssessmentContext.from_mappings(
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
    },
    protocol_metadata={"ipsec_detected": True, "esp_packets": 100},
)
assessment = SecurityAssessmentEngine().assess(context)
```

A `DatasetRecord` can be assessed directly with `SecurityAssessmentEngine.assess_record(record)`.

## Rules

The default rules cover cryptographic strength, cipher strength, configuration compliance, SA parameters, key lifetime, replay protection, PFS, authentication configuration, DH/key-exchange strength, and metadata exposure.

Every finding contains a category, severity, title, evidence, explanation, recommendation, and `observed`, `inferred`, or `unavailable` status. Missing key lifetime, replay protection, endpoint metadata, or other settings are reported as unavailable and are never assumed to be secure or insecure.

Rules are configurable by passing `SecurityRuleConfig` and replaceable or extendable by passing `AssessmentRule` objects to `SecurityAssessmentEngine`.

## Limitations

- A finding reflects only the supplied configuration and observations; it does not prove the state of a peer that was not captured or configured.
- Metadata exposure is limited to endpoint/flow metadata provided by the caller.
- The engine does not inspect encrypted payload contents.
- The engine does not calculate a security score or claim compliance beyond the configured checks.
