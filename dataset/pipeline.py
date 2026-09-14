from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence

from packet_engine.features import extract_features_from_pcap

from .models import DatasetManifest, DatasetRecord, ValidationReport

REQUIRED_TRAFFIC_TYPES = {"icmp", "tcp", "udp", "iperf"}
DEFAULT_SPLIT_RATIOS = {"train": 0.70, "validation": 0.15, "test": 0.15}


def _observation_value(value: Any) -> Any:
    if isinstance(value, Mapping) and "value" in value and "status" in value:
        return value.get("value")
    return value


def _model_to_values(model: Any) -> Dict[str, Any]:
    values: Dict[str, Any] = {}
    for name, field_value in model.model_dump().items():
        if name == "preprocessing":
            continue
        values[name] = _observation_value(field_value)
    return values


def _single_traffic_type(meta: Mapping[str, Any], labels: Mapping[str, Any]) -> str:
    value = meta.get("traffic_type", labels.get("traffic_type"))
    if value is None:
        configured = labels.get("traffic_types")
        if isinstance(configured, list) and len(configured) == 1:
            value = configured[0]
    if not isinstance(value, str) or value not in REQUIRED_TRAFFIC_TYPES:
        raise ValueError(
            "capture must declare exactly one traffic_type; run the testbed once "
            "per traffic type instead of combining traffic generators"
        )
    return value


def _load_json(path: Path) -> Dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read JSON metadata {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"metadata must be a JSON object: {path}")
    return value


def load_capture_record(pcap_path: str | Path, meta_path: str | Path | None = None) -> DatasetRecord:
    """Analyze one PCAP and sidecar, producing a capture-level dataset record."""

    pcap = Path(pcap_path)
    if not pcap.is_file():
        raise ValueError(f"PCAP does not exist: {pcap}")
    metadata_path = Path(meta_path) if meta_path else Path(f"{pcap}.meta.json")
    if not metadata_path.is_file():
        raise ValueError(f"capture metadata sidecar is missing: {metadata_path}")

    meta = _load_json(metadata_path)
    labels = meta.get("labels")
    if not isinstance(labels, dict):
        raise ValueError(f"labels are missing or invalid: {metadata_path}")
    scenario_id = meta.get("scenario_id")
    if not isinstance(scenario_id, str) or not scenario_id:
        raise ValueError(f"scenario_id is missing: {metadata_path}")

    capture_id = meta.get("capture_id") or pcap.stem
    if not isinstance(capture_id, str) or not capture_id:
        raise ValueError(f"capture_id is missing: {metadata_path}")

    analysis = extract_features_from_pcap(pcap)
    features = analysis.derived_flow_features
    protocol = analysis.deterministic_protocol_info
    traffic_type = _single_traffic_type(meta, labels)
    vpn_keys = (
        "ipsec_mode", "ike_version", "encryption", "integrity", "prf",
        "dh_group", "pfs_enabled", "ip_version", "auth_method",
    )
    vpn_configuration = {key: labels.get(key) for key in vpn_keys}
    vpn_configuration["scenario_name"] = meta.get("scenario_name")

    return DatasetRecord(
        capture_id=capture_id,
        scenario_id=scenario_id,
        pcap_file=str(pcap.resolve()),
        traffic_type=traffic_type,
        vpn_configuration=vpn_configuration,
        protocol_metadata={
            "ipsec_detected": _observation_value(protocol.ipsec_detected.model_dump()),
            "ike_detected": _observation_value(protocol.ike_detected.model_dump()),
            "ike_version": _observation_value(protocol.ike_version.model_dump()),
            "protocol_names": _observation_value(protocol.protocol_names.model_dump()),
            "esp_packets": _observation_value(protocol.esp_packets.model_dump()),
            "ah_packets": _observation_value(protocol.ah_packets.model_dump()),
        },
        flow_features=_model_to_values(features),
        labels={
            "traffic_type": traffic_type,
            "scenario_id": scenario_id,
            "ipsec_mode": labels.get("ipsec_mode"),
            "encryption": labels.get("encryption"),
            "ip_version": labels.get("ip_version"),
        },
    )


def _assign_splits(records: Sequence[DatasetRecord], seed: int, ratios: Mapping[str, float]) -> List[DatasetRecord]:
    if set(ratios) != {"train", "validation", "test"}:
        raise ValueError("split_ratios must contain train, validation, and test")
    if any(r <= 0 for r in ratios.values()) or abs(sum(ratios.values()) - 1.0) > 1e-9:
        raise ValueError("split ratios must be positive and sum to 1")

    groups = sorted({record.scenario_id for record in records})
    if len(groups) < 3:
        raise ValueError("at least three distinct scenarios are required for three leakage-safe splits")
    ordered = sorted(groups, key=lambda group: hashlib.sha256(f"{seed}:{group}".encode()).hexdigest())
    target_counts = {
        "train": max(1, round(len(groups) * ratios["train"])),
        "validation": max(1, round(len(groups) * ratios["validation"])),
    }
    target_counts["test"] = len(groups) - target_counts["train"] - target_counts["validation"]
    while target_counts["test"] < 1:
        target_counts["train"] -= 1
        target_counts["test"] += 1
    assignments: Dict[str, str] = {}
    cursor = 0
    for split in ("train", "validation", "test"):
        for group in ordered[cursor:cursor + target_counts[split]]:
            assignments[group] = split
        cursor += target_counts[split]
    return [record.model_copy(update={"split": assignments[record.scenario_id]}) for record in records]


def validate_manifest(manifest: DatasetManifest) -> ValidationReport:
    errors: List[str] = []
    warnings: List[str] = []
    seen_capture: Dict[str, str] = {}
    scenario_splits: Dict[str, set[str]] = defaultdict(set)

    for index, record in enumerate(manifest.records):
        prefix = f"record {index}"
        if not record.capture_id or not record.scenario_id or not record.pcap_file:
            errors.append(f"{prefix}: capture_id, scenario_id, and pcap_file are required")
        if record.traffic_type not in REQUIRED_TRAFFIC_TYPES:
            errors.append(f"{prefix}: invalid traffic_type {record.traffic_type!r}")
        if not record.labels.get("traffic_type"):
            errors.append(f"{prefix}: missing ground-truth traffic label")
        if record.labels.get("traffic_type") != record.traffic_type:
            errors.append(f"{prefix}: labels.traffic_type disagrees with traffic_type")
        if record.capture_id in seen_capture and seen_capture[record.capture_id] != record.split:
            errors.append(f"{prefix}: capture appears in multiple splits")
        seen_capture[record.capture_id] = record.split
        scenario_splits[record.scenario_id].add(record.split)

    for scenario_id, splits in scenario_splits.items():
        if len(splits) > 1:
            errors.append(f"scenario group {scenario_id} appears in multiple splits: {sorted(splits)}")
    if not manifest.records:
        errors.append("dataset contains no records")
    if len(scenario_splits) < 3:
        warnings.append("fewer than three scenarios are present; three-way scenario-level splitting is not possible")

    return ValidationReport(
        valid=not errors,
        record_count=len(manifest.records),
        errors=errors,
        warnings=warnings,
    )


def _capture_files(raw_dir: Path) -> Iterable[Path]:
    return sorted(path for path in raw_dir.glob("*.pcap") if path.is_file())


def build_dataset(
    raw_dir: str | Path,
    output_dir: str | Path,
    *,
    seed: int = 26160,
    split_ratios: Mapping[str, float] | None = None,
) -> DatasetManifest:
    """Build JSONL train/validation/test manifests from capture sidecars."""

    raw = Path(raw_dir)
    output = Path(output_dir)
    if not raw.is_dir():
        raise ValueError(f"raw capture directory does not exist: {raw}")
    records: List[DatasetRecord] = []
    errors: List[str] = []
    for pcap in _capture_files(raw):
        try:
            records.append(load_capture_record(pcap))
        except ValueError as exc:
            errors.append(str(exc))
    if errors:
        raise ValueError("dataset records are invalid:\n" + "\n".join(errors))

    assigned = _assign_splits(records, seed, split_ratios or DEFAULT_SPLIT_RATIOS)
    manifest = DatasetManifest(
        split_seed=seed,
        split_ratios=dict(split_ratios or DEFAULT_SPLIT_RATIOS),
        records=assigned,
    )
    report = validate_manifest(manifest)
    if not report.valid:
        raise ValueError("dataset validation failed:\n" + "\n".join(report.errors))

    output.mkdir(parents=True, exist_ok=True)
    (output / "manifest.json").write_text(
        json.dumps({**manifest.model_dump(), "generated_at": datetime.now(timezone.utc).isoformat()}, indent=2),
        encoding="utf-8",
    )
    for split in ("train", "validation", "test"):
        rows = [record.model_dump() for record in assigned if record.split == split]
        (output / f"{split}.jsonl").write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
            encoding="utf-8",
        )
    (output / "validation.json").write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return manifest
