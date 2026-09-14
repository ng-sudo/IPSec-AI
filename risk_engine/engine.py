from __future__ import annotations

from typing import Dict, Iterable, List, Mapping, Sequence

from security_engine.models import AssessmentFinding, SecurityAssessment

from .models import (
    CategoryScore,
    RiskAssessment,
    RiskLevel,
    ScoringConfig,
    ScoreStatus,
    ThreatRiskMatrixEntry,
)

CATEGORY_FINDINGS = {
    "cryptographic_strength": {"cryptographic_strength", "cipher_strength", "dh_key_exchange_strength", "dh-strength", "cipher-strength"},
    "configuration_compliance": {"configuration_compliance", "authentication_configuration", "authentication"},
    "sa_security": {"sa_parameters", "sa-parameters"},
    "key_management": {"key_lifetime", "key-lifetime"},
    "replay_protection": {"replay_protection", "replay-protection"},
    "pfs": {"pfs"},
    "metadata_exposure": {"metadata_exposure"},
}

SEVERITY_LIKELIHOOD = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def _findings_for_category(findings: Sequence[AssessmentFinding], category: str) -> List[AssessmentFinding]:
    rule_ids = CATEGORY_FINDINGS[category]
    return [finding for finding in findings if finding.category == category or finding.rule_id in rule_ids]


def _score_finding(finding: AssessmentFinding, config: ScoringConfig) -> float | None:
    if finding.status == "unavailable":
        return None
    penalty = config.severity_penalties.get(finding.severity)
    if penalty is None:
        raise ValueError(f"no scoring penalty configured for severity {finding.severity!r}")
    return round(100.0 * (1.0 - penalty), 2)


def _risk_from_score(score: float | None) -> RiskLevel:
    if score is None:
        return "insufficient_data"
    if score >= 80:
        return "info"
    if score >= 60:
        return "low"
    if score >= 40:
        return "moderate"
    if score >= 20:
        return "high"
    return "critical"


def _score_status(findings: Sequence[AssessmentFinding], known: Sequence[float | None]) -> ScoreStatus:
    if not known:
        return "unavailable"
    if any(finding.status == "unavailable" for finding in findings):
        return "partial"
    return "complete"


def _matrix_likelihood(findings: Sequence[AssessmentFinding]) -> int | None:
    observed = [SEVERITY_LIKELIHOOD[finding.severity] for finding in findings if finding.status != "unavailable"]
    return max(observed) if observed else None


class RiskScoringEngine:
    """Deterministically score a SecurityAssessment using configurable project rules."""

    def __init__(self, config: ScoringConfig | None = None):
        self.config = config or ScoringConfig()

    def score(self, assessment: SecurityAssessment) -> RiskAssessment:
        category_scores: List[CategoryScore] = []
        matrix: List[ThreatRiskMatrixEntry] = []
        known_weight = 0.0
        weighted_sum = 0.0
        evidence: List[str] = []

        for category, weight in self.config.weights.items():
            findings = _findings_for_category(assessment.findings, category)
            scores = [_score_finding(finding, self.config) for finding in findings]
            known_scores = [score for score in scores if score is not None]
            status = _score_status(findings, scores)
            category_score = round(sum(known_scores) / len(known_scores), 2) if known_scores else None
            contribution = round(category_score * weight, 2) if category_score is not None else None
            if category_score is not None:
                known_weight += weight
                weighted_sum += category_score * weight
            category_evidence = [
                f"{finding.rule_id} [{finding.status}]: {finding.evidence}" for finding in findings
            ]
            rule_ids = [finding.rule_id for finding in findings]
            category_scores.append(CategoryScore(
                category=category,
                weight=weight,
                score=category_score,
                weighted_contribution=contribution,
                status=status,
                finding_count=len(findings),
                known_finding_count=len(known_scores),
                evidence=category_evidence,
                finding_rule_ids=rule_ids,
            ))
            if category_evidence:
                evidence.extend(f"{category}: {item}" for item in category_evidence)
            matrix.append(ThreatRiskMatrixEntry(
                category=category,
                security_score=category_score,
                risk_level="insufficient_data" if status != "complete" else _risk_from_score(category_score),
                likelihood=_matrix_likelihood(findings),
                impact=self.config.category_impacts[category],
                status=status,
                evidence=category_evidence,
            ))

        score_status: ScoreStatus
        if known_weight == 0:
            score_status = "unavailable"
            overall_score = None
        elif known_weight < 1.0:
            score_status = "partial"
            overall_score = round(weighted_sum / known_weight, 2)
        else:
            score_status = "complete"
            overall_score = round(weighted_sum, 2)
        risk_level: RiskLevel = "insufficient_data" if score_status != "complete" else _risk_from_score(overall_score)

        return RiskAssessment(
            methodology_version=self.config.methodology_version,
            overall_score=overall_score,
            risk_level=risk_level,
            score_status=score_status,
            known_weight=round(known_weight, 4),
            category_scores=category_scores,
            threat_risk_matrix=matrix,
            evidence=evidence,
        )

    def score_findings(self, findings: Iterable[AssessmentFinding]) -> RiskAssessment:
        findings_list = list(findings)
        assessment = SecurityAssessment.model_validate({
            "findings": [finding.model_dump() for finding in findings_list],
            "summary": {
                "finding_count": len(findings_list),
                "severity_counts": {},
                "status_counts": {},
            },
        })
        return self.score(assessment)
