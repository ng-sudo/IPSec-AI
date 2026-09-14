from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence

from .models import ReportDocument, ReportField, ReportFinding, ReportSection, ReportBundle, Status


class ReportInputError(ValueError):
    """Raised when a report input is not a structured analysis result."""


def _mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if hasattr(value, "model_dump"):
        return value.model_dump()
    raise ReportInputError("analysis result must be a mapping or a Pydantic model")


def _get(data: Mapping[str, Any], *path: str) -> Any:
    current: Any = data
    for key in path:
        if not isinstance(current, Mapping) or key not in current:
            return None
        current = current[key]
    return current


def _observation(raw: Any) -> tuple[Any, Status, str | None]:
    if isinstance(raw, Mapping) and "status" in raw and "value" in raw:
        status = raw.get("status")
        if status not in {"observed", "inferred", "unavailable"}:
            status = "unavailable"
        return raw.get("value"), status, raw.get("notes")
    if raw is None:
        return None, "unavailable", None
    return raw, "observed", None


def _field(label: str, raw: Any, evidence: str | None = None) -> ReportField:
    value, status, notes = _observation(raw)
    return ReportField(label=label, value=value, status=status, evidence=evidence or notes)


def _finding(raw: Mapping[str, Any]) -> ReportFinding:
    value, status, _ = _observation(raw.get("status", "unavailable"))
    return ReportFinding(
        title=str(raw.get("title") or "Untitled finding"),
        category=str(raw.get("category") or "unclassified"),
        severity=str(raw.get("severity") or "info"),
        status=status,
        evidence=str(raw.get("evidence") or "Evidence unavailable."),
        explanation=str(raw.get("explanation") or "Explanation unavailable."),
        recommendation=str(raw.get("recommendation") or "Recommendation unavailable."),
    )


def _findings(data: Mapping[str, Any]) -> List[ReportFinding]:
    raw_findings = _get(data, "security_assessment", "findings") or []
    return [_finding(item) for item in raw_findings if isinstance(item, Mapping)]


def _limitations(data: Mapping[str, Any]) -> List[str]:
    limitations = [
        "This report reflects only the supplied capture, configuration, and deterministic assessment results.",
        "Encrypted payload contents were not inspected.",
    ]
    unavailable: List[str] = []
    for field in (
        ("prediction", "predicted_traffic_type"),
        ("prediction", "confidence"),
        ("metadata_inference", "source_ip"),
        ("metadata_inference", "destination_ip"),
    ):
        raw = _get(data, *field)
        _, status, _ = _observation(raw)
        if status == "unavailable":
            unavailable.append(".".join(field))
    if unavailable:
        limitations.append("Unavailable inputs remain explicitly unreported: " + ", ".join(unavailable) + ".")
    risk_status = _get(data, "risk_assessment", "score_status")
    if risk_status and risk_status != "complete":
        limitations.append(f"Risk scoring is {risk_status}; missing weighted categories limit the conclusion.")
    return limitations


def _render_value(field: ReportField) -> str:
    value = "Unavailable" if field.status == "unavailable" or field.value is None else json.dumps(field.value, ensure_ascii=True) if isinstance(field.value, (dict, list)) else str(field.value)
    return f"{value} (`{field.status}`)"


def _render_markdown(document: ReportDocument) -> str:
    lines = [f"# {document.title}", "", f"**Capture:** `{document.capture_id}`", "", "Information status is shown as `observed`, `inferred`, or `unavailable`.", ""]
    for section in document.sections:
        lines.extend([f"## {section.title}", ""])
        if section.summary:
            lines.extend([section.summary, ""])
        if section.fields:
            for field in section.fields:
                evidence = f" Evidence: {field.evidence}" if field.evidence else ""
                lines.append(f"- **{field.label}:** {_render_value(field)}.{evidence}")
            lines.append("")
        for finding in section.findings:
            lines.extend([
                f"### {finding.title} ({finding.severity}, {finding.status})",
                f"- **Category:** {finding.category}",
                f"- **Evidence:** {finding.evidence}",
                f"- **Explanation:** {finding.explanation}",
                f"- **Recommendation:** {finding.recommendation}",
                "",
            ])
        if section.recommendations:
            lines.append("**Recommendations**")
            lines.extend(f"- {recommendation}" for recommendation in section.recommendations)
            lines.append("")
    lines.extend(["## Limitations", ""])
    lines.extend(f"- {limitation}" for limitation in document.limitations)
    lines.append("")
    return "\n".join(lines)


def _common_sections(data: Mapping[str, Any]) -> tuple[ReportSection, ReportSection, ReportSection]:
    packet = _get(data, "packet_analysis") or {}
    protocol = _get(data, "metadata_inference") or {}
    config = _get(data, "vpn_configuration") or {}
    prediction = _get(data, "prediction") or {}
    flow = _get(data, "features", "derived_flow_features") or {}
    findings = _findings(data)
    risk = _get(data, "risk_assessment") or {}

    identification = ReportSection(
        title="IPsec / IKE identification",
        fields=[
            _field("IPsec detected", protocol.get("ipsec_detected")),
            _field("IKE version", protocol.get("ike_version")),
            _field("IKE detected", protocol.get("ike_detected")),
            _field("IPsec protocols", packet.get("ipsec_protocols")),
            _field("IPsec mode", config.get("ipsec_mode")),
        ],
    )
    configuration = ReportSection(
        title="VPN configuration",
        fields=[_field(label.replace("_", " ").title(), config.get(label)) for label in (
            "encryption", "integrity", "prf", "auth_method", "dh_group", "ip_version", "pfs_enabled", "replay_protection", "key_lifetime_seconds"
        )],
    )
    traffic = ReportSection(
        title="Traffic analysis",
        fields=[
            _field("Packet count", packet.get("packet_summary", {}).get("packet_count")),
            _field("Byte count", packet.get("packet_summary", {}).get("byte_count")),
            _field("Flow duration seconds", packet.get("packet_summary", {}).get("duration_seconds")),
            _field("Mean packet size", flow.get("packet_size_mean")),
            _field("Mean inter-arrival", flow.get("inter_arrival_mean")),
            _field("Packets per second", flow.get("packets_per_second")),
            _field("Bytes per second", flow.get("bytes_per_second")),
            _field("ESP packet ratio", flow.get("esp_packet_ratio")),
        ],
    )
    ai = ReportSection(
        title="AI traffic classification",
        fields=[
            _field("Predicted traffic type", prediction.get("predicted_traffic_type")),
            _field("AI confidence", prediction.get("confidence")),
            _field("Model version", prediction.get("model_version")),
        ],
    )
    findings_section = ReportSection(title="Security findings", findings=findings)
    cryptographic = ReportSection(
        title="Cryptographic assessment",
        findings=[finding for finding in findings if finding.category in {"cryptographic_strength", "cipher_strength", "dh_key_exchange_strength"}],
    )
    controls = ReportSection(
        title="Security controls",
        fields=[
            _field("Replay protection", config.get("replay_protection")),
            _field("PFS", config.get("pfs_enabled")),
            _field("Key lifetime", config.get("key_lifetime_seconds")),
            _field("Source IP metadata", protocol.get("source_ip")),
            _field("Destination IP metadata", protocol.get("destination_ip")),
            _field("Encrypted payload contents", protocol.get("encrypted_payload_contents")),
        ],
        findings=[finding for finding in findings if finding.category in {"replay_protection", "pfs", "key_lifetime", "metadata_exposure"}],
    )
    score = ReportSection(
        title="Security and risk score",
        fields=[
            _field("Overall security score", risk.get("overall_score")),
            _field("Risk level", risk.get("risk_level")),
            _field("Score status", risk.get("score_status")),
            _field("Known weight", risk.get("known_weight")),
        ],
    )
    matrix = ReportSection(
        title="Threat / risk matrix",
        fields=[_field("Matrix entries", risk.get("threat_risk_matrix"))],
    )
    return identification, configuration, traffic, ai, findings_section, cryptographic, controls, score, matrix


def generate_executive_report(analysis: Any) -> ReportDocument:
    data = _mapping(analysis)
    sections = _common_sections(data)
    identification, configuration, traffic, ai, findings, cryptographic, controls, score, matrix = sections
    risk = _get(data, "risk_assessment") or {}
    executive_summary = ReportSection(
        title="Analysis summary",
        summary="This executive report summarizes the supplied IPSecAI analysis result. It contains no values beyond the capture analysis, configuration, assessment, and scoring inputs.",
        fields=[
            _field("Capture ID", data.get("capture_id")),
            _field("Risk level", risk.get("risk_level")),
            _field("Overall security score", risk.get("overall_score")),
            _field("Score completeness", risk.get("score_status")),
        ],
    )
    recommendations = sorted({finding.recommendation for finding in findings.findings if finding.status != "unavailable"})
    executive_recommendations = ReportSection(title="Recommendations", recommendations=recommendations or ["No actionable recommendation was available from the supplied findings."])
    document = ReportDocument(report_type="executive", title="IPSecAI Executive Security Report", capture_id=str(data.get("capture_id") or "unavailable"), sections=[executive_summary, score, identification, ai, findings, executive_recommendations], limitations=_limitations(data))
    document.markdown = _render_markdown(document)
    return document


def generate_technical_report(analysis: Any) -> ReportDocument:
    data = _mapping(analysis)
    identification, configuration, traffic, ai, findings, cryptographic, controls, score, matrix = _common_sections(data)
    recommendations = sorted({finding.recommendation for finding in findings.findings if finding.status != "unavailable"})
    recommendations_section = ReportSection(title="Recommendations", recommendations=recommendations or ["No actionable recommendation was available from the supplied findings."])
    document = ReportDocument(report_type="technical", title="IPSecAI Technical Analysis Report", capture_id=str(data.get("capture_id") or "unavailable"), sections=[identification, configuration, traffic, ai, findings, cryptographic, controls, score, matrix, recommendations_section], limitations=_limitations(data))
    document.markdown = _render_markdown(document)
    return document


def generate_reports(analysis: Any) -> ReportBundle:
    return ReportBundle(executive=generate_executive_report(analysis), technical=generate_technical_report(analysis))


def write_reports(analysis: Any, output_dir: str | Path) -> ReportBundle:
    bundle = generate_reports(analysis)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    for filename, content in bundle.as_markdown_files().items():
        (output / filename).write_text(content, encoding="utf-8")
    (output / "reports.json").write_text(bundle.model_dump_json(indent=2), encoding="utf-8")
    return bundle
