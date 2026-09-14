from __future__ import annotations

import statistics
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from .analyzer import analyze_pcap
from .models import Observation


class FeaturePreprocessing(BaseModel):
    """Defines reproducible preprocessing for ML-ready features."""

    version: str = "1.0"
    sort_order: str = "packet_index"
    missing_value_policy: str = "preserve_unavailable"
    payload_exclusion: str = "encrypted_payload_contents_excluded"


class RawPacketInfo(BaseModel):
    packet_count: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    packets: List[Dict[str, Any]] = Field(default_factory=list)


class DeterministicProtocolInfo(BaseModel):
    ipsec_detected: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    ike_detected: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    ike_version: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    protocol_names: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    esp_packets: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    ah_packets: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    spi_values: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    sequence_values: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    protocol_metadata: Observation = Field(default_factory=lambda: Observation(status="unavailable"))


class DerivedFlowFeatures(BaseModel):
    packet_count: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    byte_count: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    packet_size_min: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    packet_size_max: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    packet_size_mean: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    packet_size_variance: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    packet_size_stddev: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    inter_arrival_min: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    inter_arrival_max: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    inter_arrival_mean: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    flow_duration_seconds: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    packets_per_second: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    bytes_per_second: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    directionality: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    esp_packet_ratio: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    unique_spi_count: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    sequence_span: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    sequence_delta_mean: Observation = Field(default_factory=lambda: Observation(status="unavailable"))
    source_destination_summary: Observation = Field(default_factory=lambda: Observation(status="unavailable"))


class MLFeature(BaseModel):
    name: str
    value: Any = None
    status: str = "observed"
    source: str = "derived"


class MLFeatureVector(BaseModel):
    preprocessing: FeaturePreprocessing = Field(default_factory=FeaturePreprocessing)
    features: List[MLFeature] = Field(default_factory=list)


class FeatureExtractionResult(BaseModel):
    raw_packet_info: RawPacketInfo = Field(default_factory=RawPacketInfo)
    deterministic_protocol_info: DeterministicProtocolInfo = Field(default_factory=DeterministicProtocolInfo)
    derived_flow_features: DerivedFlowFeatures = Field(default_factory=DerivedFlowFeatures)
    ml_features: MLFeatureVector = Field(default_factory=MLFeatureVector)


def _safe_float(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _packets_to_raw_info(packets: List[Dict[str, Any]]) -> RawPacketInfo:
    if not packets:
        return RawPacketInfo(
            packet_count=Observation(status="unavailable", value=None, notes="No packets were available."),
            packets=[],
        )

    packet_list = [
        {
            "index": p.get("index"),
            "timestamp": p.get("timestamp", {}).get("value"),
            "src_ip": p.get("src_ip", {}).get("value"),
            "dst_ip": p.get("dst_ip", {}).get("value"),
            "src_port": p.get("src_port", {}).get("value"),
            "dst_port": p.get("dst_port", {}).get("value"),
            "protocol": p.get("protocol", {}).get("value"),
            "length": p.get("length", {}).get("value"),
            "spi": p.get("spi", {}).get("value"),
            "sequence": p.get("sequence", {}).get("value"),
            "ike_version": p.get("ike_version", {}).get("value"),
            "ipsec_type": p.get("ipsec_type", {}).get("value"),
        }
        for p in packets
    ]
    return RawPacketInfo(
        packet_count=Observation(status="observed", value=len(packet_list), notes="Packet list was retained without payload content."),
        packets=packet_list,
    )


def _extract_protocol_info(result: Any) -> DeterministicProtocolInfo:
    protocols = []
    for pkt in result.packets:
        value = pkt.protocol.value if getattr(pkt, "protocol", None) else None
        if value not in (None, "unknown"):
            protocols.append(str(value))

    spi_values = []
    sequence_values = []
    for pkt in result.packets:
        if pkt.spi.value is not None:
            spi_values.append(pkt.spi.value)
        if pkt.sequence.value is not None:
            sequence_values.append(pkt.sequence.value)

    return DeterministicProtocolInfo(
        ipsec_detected=result.ipsec_detected,
        ike_detected=result.ike_detected,
        ike_version=result.ike_version,
        protocol_names=Observation(
            status="observed" if protocols else "unavailable",
            value=sorted(set(protocols)) if protocols else None,
            notes="Protocol labels from packet headers only; encrypted payload contents excluded.",
        ),
        esp_packets=result.esp_packets,
        ah_packets=result.ah_packets,
        spi_values=Observation(
            status="observed" if spi_values else "unavailable",
            value=spi_values if spi_values else None,
        ),
        sequence_values=Observation(
            status="observed" if sequence_values else "unavailable",
            value=sequence_values if sequence_values else None,
        ),
        protocol_metadata=Observation(
            status="observed" if protocols else "unavailable",
            value={
                "protocols": sorted(set(protocols)),
                "esp_packet_count": result.esp_packets.value if result.esp_packets.status == "observed" else 0,
                "ah_packet_count": result.ah_packets.value if result.ah_packets.status == "observed" else 0,
            },
        ),
    )


def _extract_derived_flow_features(result: Any) -> DerivedFlowFeatures:
    packet_lengths = [float(pkt.length.value) for pkt in result.packets if _safe_float(pkt.length.value) is not None]
    timestamps = [float(pkt.timestamp.value) for pkt in result.packets if _safe_float(pkt.timestamp.value) is not None]
    packet_count = len(result.packets)
    byte_count = result.packet_summary.byte_count.value if result.packet_summary.byte_count.status == "observed" else sum(packet_lengths)

    if packet_lengths:
        min_len = min(packet_lengths)
        max_len = max(packet_lengths)
        mean_len = sum(packet_lengths) / len(packet_lengths)
        variance = statistics.pvariance(packet_lengths) if len(packet_lengths) > 1 else 0.0
        stddev = statistics.pstdev(packet_lengths) if len(packet_lengths) > 1 else 0.0
    else:
        min_len = max_len = mean_len = variance = stddev = None

    if len(timestamps) >= 2:
        inter_arrivals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        iat_min = min(inter_arrivals)
        iat_max = max(inter_arrivals)
        iat_mean = sum(inter_arrivals) / len(inter_arrivals)
    else:
        inter_arrivals = []
        iat_min = iat_max = iat_mean = None

    flow_duration = result.packet_summary.duration_seconds.value if result.packet_summary.duration_seconds.status == "observed" else None
    if flow_duration is not None and flow_duration > 0:
        packets_per_second = packet_count / float(flow_duration)
        bytes_per_second = byte_count / float(flow_duration)
    else:
        packets_per_second = bytes_per_second = None

    directionality = None
    if result.flow_summary.src_ip.status == "observed" or result.flow_summary.dst_ip.status == "observed":
        directionality = 1.0 if packet_count > 0 else 0.0

    esp_count = result.esp_packets.value if result.esp_packets.status == "observed" else 0
    esp_ratio = (esp_count / packet_count) if packet_count else None

    spi_list = [pkt.spi.value for pkt in result.packets if pkt.spi.value is not None]
    unique_spi_count = len(set(spi_list)) if spi_list else 0

    seq_list = [pkt.sequence.value for pkt in result.packets if pkt.sequence.value is not None]
    if seq_list:
        seq_span = max(seq_list) - min(seq_list)
        deltas = [b - a for a, b in zip(seq_list, seq_list[1:]) if _safe_float(a) is not None and _safe_float(b) is not None]
        sequence_delta_mean = sum(deltas) / len(deltas) if deltas else 0.0
    else:
        seq_span = None
        sequence_delta_mean = None

    return DerivedFlowFeatures(
        packet_count=Observation(status="observed" if packet_count else "unavailable", value=packet_count),
        byte_count=Observation(status="observed" if byte_count is not None else "unavailable", value=byte_count),
        packet_size_min=Observation(status="observed" if min_len is not None else "unavailable", value=min_len),
        packet_size_max=Observation(status="observed" if max_len is not None else "unavailable", value=max_len),
        packet_size_mean=Observation(status="observed" if mean_len is not None else "unavailable", value=mean_len),
        packet_size_variance=Observation(status="observed" if variance is not None else "unavailable", value=variance),
        packet_size_stddev=Observation(status="observed" if stddev is not None else "unavailable", value=stddev),
        inter_arrival_min=Observation(status="observed" if iat_min is not None else "unavailable", value=iat_min),
        inter_arrival_max=Observation(status="observed" if iat_max is not None else "unavailable", value=iat_max),
        inter_arrival_mean=Observation(status="observed" if iat_mean is not None else "unavailable", value=iat_mean),
        flow_duration_seconds=Observation(status="observed" if flow_duration is not None else "unavailable", value=flow_duration),
        packets_per_second=Observation(status="observed" if packets_per_second is not None else "unavailable", value=packets_per_second),
        bytes_per_second=Observation(status="observed" if bytes_per_second is not None else "unavailable", value=bytes_per_second),
        directionality=Observation(status="inferred" if directionality is not None else "unavailable", value=directionality),
        esp_packet_ratio=Observation(status="observed" if esp_ratio is not None else "unavailable", value=esp_ratio),
        unique_spi_count=Observation(status="observed" if unique_spi_count else "unavailable", value=unique_spi_count),
        sequence_span=Observation(status="observed" if seq_span is not None else "unavailable", value=seq_span),
        sequence_delta_mean=Observation(status="observed" if sequence_delta_mean is not None else "unavailable", value=sequence_delta_mean),
        source_destination_summary=Observation(
            status="observed" if result.flow_summary.src_ip.status == "observed" or result.flow_summary.dst_ip.status == "observed" else "unavailable",
            value={
                "src_ip": result.flow_summary.src_ip.value,
                "dst_ip": result.flow_summary.dst_ip.value,
                "flow_direction": result.flow_summary.flow_direction.value,
            },
        ),
    )


def _feature_list_from_derived(derived: DerivedFlowFeatures) -> List[MLFeature]:
    return [
        MLFeature(name="packet_count", value=derived.packet_count.value, status=derived.packet_count.status, source="derived"),
        MLFeature(name="byte_count", value=derived.byte_count.value, status=derived.byte_count.status, source="derived"),
        MLFeature(name="packet_size_min", value=derived.packet_size_min.value, status=derived.packet_size_min.status, source="derived"),
        MLFeature(name="packet_size_max", value=derived.packet_size_max.value, status=derived.packet_size_max.status, source="derived"),
        MLFeature(name="packet_size_mean", value=derived.packet_size_mean.value, status=derived.packet_size_mean.status, source="derived"),
        MLFeature(name="packet_size_variance", value=derived.packet_size_variance.value, status=derived.packet_size_variance.status, source="derived"),
        MLFeature(name="packet_size_stddev", value=derived.packet_size_stddev.value, status=derived.packet_size_stddev.status, source="derived"),
        MLFeature(name="inter_arrival_min", value=derived.inter_arrival_min.value, status=derived.inter_arrival_min.status, source="derived"),
        MLFeature(name="inter_arrival_max", value=derived.inter_arrival_max.value, status=derived.inter_arrival_max.status, source="derived"),
        MLFeature(name="inter_arrival_mean", value=derived.inter_arrival_mean.value, status=derived.inter_arrival_mean.status, source="derived"),
        MLFeature(name="flow_duration_seconds", value=derived.flow_duration_seconds.value, status=derived.flow_duration_seconds.status, source="derived"),
        MLFeature(name="packets_per_second", value=derived.packets_per_second.value, status=derived.packets_per_second.status, source="derived"),
        MLFeature(name="bytes_per_second", value=derived.bytes_per_second.value, status=derived.bytes_per_second.status, source="derived"),
        MLFeature(name="directionality", value=derived.directionality.value, status=derived.directionality.status, source="derived"),
        MLFeature(name="esp_packet_ratio", value=derived.esp_packet_ratio.value, status=derived.esp_packet_ratio.status, source="derived"),
        MLFeature(name="unique_spi_count", value=derived.unique_spi_count.value, status=derived.unique_spi_count.status, source="derived"),
        MLFeature(name="sequence_span", value=derived.sequence_span.value, status=derived.sequence_span.status, source="derived"),
        MLFeature(name="sequence_delta_mean", value=derived.sequence_delta_mean.value, status=derived.sequence_delta_mean.status, source="derived"),
    ]


def extract_features_from_analysis(result: Any) -> FeatureExtractionResult:
    """Build a reproducible, ML-ready feature record from packet-analysis output."""

    raw_packet_info = _packets_to_raw_info([
        {
            "index": pkt.index,
            "timestamp": pkt.timestamp.model_dump(),
            "src_ip": pkt.src_ip.model_dump(),
            "dst_ip": pkt.dst_ip.model_dump(),
            "src_port": pkt.src_port.model_dump(),
            "dst_port": pkt.dst_port.model_dump(),
            "protocol": pkt.protocol.model_dump(),
            "length": pkt.length.model_dump(),
            "spi": pkt.spi.model_dump(),
            "sequence": pkt.sequence.model_dump(),
            "ike_version": pkt.ike_version.model_dump(),
            "ipsec_type": pkt.ipsec_type.model_dump(),
        }
        for pkt in result.packets
    ])

    protocol_info = _extract_protocol_info(result)
    flow_features = _extract_derived_flow_features(result)
    ml_features = MLFeatureVector(
        preprocessing=FeaturePreprocessing(),
        features=_feature_list_from_derived(flow_features),
    )

    return FeatureExtractionResult(
        raw_packet_info=raw_packet_info,
        deterministic_protocol_info=protocol_info,
        derived_flow_features=flow_features,
        ml_features=ml_features,
    )


def extract_features_from_pcap(path: str | Path) -> FeatureExtractionResult:
    """Analyze a pcap file and return the ML-ready feature representation."""

    analysis = analyze_pcap(path)
    return extract_features_from_analysis(analysis)
