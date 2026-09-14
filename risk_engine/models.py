from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, model_validator


ScoreStatus = Literal["complete", "partial", "unavailable"]
RiskLevel = Literal["info", "low", "moderate", "high", "critical", "insufficient_data"]


DEFAULT_WEIGHTS = {
    "cryptographic_strength": 0.25,
    "configuration_compliance": 0.20,
    "sa_security": 0.15,
    "key_management": 0.15,
    "replay_protection": 0.10,
    "pfs": 0.05,
    "metadata_exposure": 0.10,
}

DEFAULT_IMPACTS = {
    "cryptographic_strength": 5,
    "configuration_compliance": 4,
    "sa_security": 4,
    "key_management": 4,
    "replay_protection": 4,
    "pfs": 3,
    "metadata_exposure": 2,
}


class ScoringConfig(BaseModel):
    """Project-specific scoring policy; not an external security standard."""

    weights: Dict[str, float] = Field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    severity_penalties: Dict[str, float] = Field(
        default_factory=lambda: {"info": 0.0, "low": 0.15, "medium": 0.40, "high": 0.70, "critical": 1.0}
    )
    category_impacts: Dict[str, int] = Field(default_factory=lambda: dict(DEFAULT_IMPACTS))
    unavailable_policy: str = "partial_score_and_insufficient_data_risk"
    methodology_version: str = "project-specific-risk-methodology/1.0"

    @model_validator(mode="after")
    def validate_policy(self) -> "ScoringConfig":
        if set(self.weights) != set(DEFAULT_WEIGHTS):
            raise ValueError("weights must define exactly the seven configured scoring categories")
        if any(weight < 0 for weight in self.weights.values()) or abs(sum(self.weights.values()) - 1.0) > 1e-9:
            raise ValueError("weights must be non-negative and sum to 1")
        if any(value < 0 or value > 1 for value in self.severity_penalties.values()):
            raise ValueError("severity penalties must be between 0 and 1")
        if any(value < 1 or value > 5 for value in self.category_impacts.values()):
            raise ValueError("category impacts must be between 1 and 5")
        return self


class CategoryScore(BaseModel):
    category: str
    weight: float
    score: Optional[float] = None
    weighted_contribution: Optional[float] = None
    status: ScoreStatus
    finding_count: int
    known_finding_count: int
    evidence: List[str] = Field(default_factory=list)
    finding_rule_ids: List[str] = Field(default_factory=list)


class ThreatRiskMatrixEntry(BaseModel):
    category: str
    security_score: Optional[float] = None
    risk_level: RiskLevel
    likelihood: Optional[int] = None
    impact: int
    status: ScoreStatus
    evidence: List[str] = Field(default_factory=list)


class RiskAssessment(BaseModel):
    methodology_version: str
    overall_score: Optional[float] = None
    risk_level: RiskLevel
    score_status: ScoreStatus
    known_weight: float
    category_scores: List[CategoryScore]
    threat_risk_matrix: List[ThreatRiskMatrixEntry]
    evidence: List[str] = Field(default_factory=list)
