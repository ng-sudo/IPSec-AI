from __future__ import annotations

from typing import Any, Dict, List, Literal, Mapping, Optional

from pydantic import BaseModel, Field


Status = Literal["observed", "inferred", "unavailable"]
Severity = Literal["info", "low", "medium", "high", "critical"]


class AssessmentFinding(BaseModel):
    rule_id: str
    category: str
    severity: Severity
    title: str
    evidence: str
    explanation: str
    recommendation: str
    status: Status
    observed_value: Any = None


class AssessmentContext(BaseModel):
    """Inputs supplied by configuration and packet analysis layers."""

    vpn_configuration: Dict[str, Any] = Field(default_factory=dict)
    protocol_metadata: Dict[str, Any] = Field(default_factory=dict)
    flow_features: Dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_mappings(
        cls,
        vpn_configuration: Mapping[str, Any] | None = None,
        protocol_metadata: Mapping[str, Any] | None = None,
        flow_features: Mapping[str, Any] | None = None,
    ) -> "AssessmentContext":
        return cls(
            vpn_configuration=dict(vpn_configuration or {}),
            protocol_metadata=dict(protocol_metadata or {}),
            flow_features=dict(flow_features or {}),
        )


class AssessmentSummary(BaseModel):
    finding_count: int
    severity_counts: Dict[str, int]
    status_counts: Dict[str, int]


class SecurityAssessment(BaseModel):
    findings: List[AssessmentFinding]
    summary: AssessmentSummary


class SecurityRuleConfig(BaseModel):
    """Configurable policy thresholds; it does not provide missing observations."""

    max_key_lifetime_seconds: int = 3600
    accepted_ike_versions: List[int] = Field(default_factory=lambda: [2])
    accepted_auth_methods: List[str] = Field(default_factory=lambda: ["cert", "psk"])
    minimum_dh_strength: Dict[str, str] = Field(
        default_factory=lambda: {"modp2048": "medium", "ecp256": "medium", "ecp384": "strong"}
    )
