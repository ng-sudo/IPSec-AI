from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Observation(BaseModel):
    """Represents whether a field is directly observed, inferred, or unavailable."""

    status: str = Field(..., description="observed | inferred | unavailable")
    value: Any = Field(default=None, description="The value if available")
    notes: Optional[str] = Field(default=None, description="Clarifying notes")


class PacketSummary(BaseModel):
    packet_count: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    byte_count: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    first_timestamp: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    last_timestamp: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    duration_seconds: Observation = Field(default_factory=lambda: Observation(status="unavailable"))


class PacketSizeStatistics(BaseModel):
    min_length: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    max_length: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    mean_length: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    median_length: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    stddev_length: Observation = Field(default_factory=lambda: Observation(status="unavailable"))


class FlowSummary(BaseModel):
    src_ip: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    dst_ip: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    src_port: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    dst_port: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    flow_direction: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    total_packets: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    total_bytes: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    duration_seconds: Observation = Field(default_factory=lambda: Observation(status="unavailable"))


class PacketObservation(BaseModel):
    index: int
    timestamp: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    src_ip: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    dst_ip: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    src_port: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    dst_port: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    protocol: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    length: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    spi: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    sequence: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    ike_version: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    ipsec_type: Observation = Field(default_factory=lambda: Observation(status="unavailable"))


class IPsecAnalysisResult(BaseModel):
    file_path: str
    ipsec_detected: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    ike_detected: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    ike_version: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    ipsec_protocols: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    esp_packets: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    ah_packets: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    packet_summary: PacketSummary = Field(default_factory=PacketSummary)
    packet_size_statistics: PacketSizeStatistics = Field(default_factory=PacketSizeStatistics)
    inter_arrival_times: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    flow_summary: FlowSummary = Field(default_factory=FlowSummary)
    packets: List[PacketObservation] = Field(default_factory=list)
