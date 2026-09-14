from __future__ import annotations

from typing import Any, Dict, List, Literal

from pydantic import BaseModel, Field


class DatasetRecord(BaseModel):
    """One capture-level sample; packets from a capture are never split apart."""

    record_schema_version: str = "1.0"
    capture_id: str
    scenario_id: str
    pcap_file: str
    traffic_type: str
    vpn_configuration: Dict[str, Any]
    protocol_metadata: Dict[str, Any]
    flow_features: Dict[str, Any]
    labels: Dict[str, Any]
    split: Literal["train", "validation", "test"] = "train"


class DatasetManifest(BaseModel):
    """Serializable dataset index and split policy."""

    schema_version: str = "1.0"
    dataset_name: str = "ipsec_esp_traffic_classification"
    split_group: str = "scenario_id"
    split_seed: int
    split_ratios: Dict[str, float]
    records: List[DatasetRecord] = Field(default_factory=list)


class ValidationReport(BaseModel):
    valid: bool
    record_count: int
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
