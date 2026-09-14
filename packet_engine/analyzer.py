from __future__ import annotations

import json
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from scapy.all import AH, ESP, IP, IPv6, UDP, rdpcap

from .models import IPsecAnalysisResult, Observation, PacketObservation, PacketSizeStatistics, PacketSummary, FlowSummary


def _obs(value: Any, status: str = "observed", notes: Optional[str] = None) -> Observation:
    return Observation(status=status, value=value, notes=notes)


def _extract_ip_fields(pkt: Any) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[int], Optional[str]]:
    ip_layer = None
    if IP in pkt:
        ip_layer = pkt[IP]
        proto = "ipv4"
    elif IPv6 in pkt:
        ip_layer = pkt[IPv6]
        proto = "ipv6"
    else:
        return None, None, None, None, "unknown"

    src_ip = getattr(ip_layer, "src", None)
    dst_ip = getattr(ip_layer, "dst", None)
    proto_num = getattr(ip_layer, "proto", None)
    if hasattr(ip_layer, "nxt"):
        proto_num = getattr(ip_layer, "nxt", proto_num)
    if proto_num is None:
        proto_name = "unknown"
    elif proto_num == 50:
        proto_name = "esp"
    elif proto_num == 51:
        proto_name = "ah"
    elif proto_num == 17:
        proto_name = "udp"
    elif proto_num == 6:
        proto_name = "tcp"
    else:
        proto_name = str(proto_num)
    return src_ip, dst_ip, proto_num, None, proto_name


def _detect_ike_version(packet: Any) -> Optional[str]:
    if UDP in packet and packet[UDP].dport in (500, 4500):
        return "ikev2_or_ikev1"
    if packet.haslayer(UDP) and packet[UDP].sport in (500, 4500):
        return "ikev2_or_ikev1"
    return None


def _safe_float(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def analyze_pcap(path: str | Path) -> IPsecAnalysisResult:
    """Analyze a PCAP/PCAPNG file and return typed extraction results."""

    pcap_path = Path(path)
    packets = rdpcap(str(pcap_path))

    ipsec_seen = False
    ike_seen = False
    ike_version = "unavailable"
    protocols = []
    esp_count = 0
    ah_count = 0
    packet_lengths: List[float] = []
    times: List[float] = []
    per_packet: List[PacketObservation] = []

    packet_total_bytes = 0
    seen_ip_packets = []

    for idx, pkt in enumerate(packets, start=1):
        timestamp = getattr(pkt.time, "_value", None)
        if timestamp is not None:
            try:
                times.append(float(timestamp))
            except (TypeError, ValueError):
                pass

        src_ip, dst_ip, proto_num, _, proto_name = _extract_ip_fields(pkt)
        if src_ip is not None and dst_ip is not None:
            seen_ip_packets.append((src_ip, dst_ip, proto_name, pkt))

        length = len(bytes(pkt))
        packet_lengths.append(float(length))
        packet_total_bytes += length

        pkt_protocols = []
        if pkt.haslayer(UDP) and pkt[UDP].dport in (500, 4500):
            ike_seen = True
            pkt_protocols.append("ike")
            protocol_name = "ike"
            ike_version = "observed"
        else:
            protocol_name = "unknown"

        if pkt.haslayer(ESP):
            ipsec_seen = True
            esp_count += 1
            pkt_protocols.append("esp")
            protocol_name = "esp"
        if pkt.haslayer(AH):
            ipsec_seen = True
            ah_count += 1
            pkt_protocols.append("ah")
            protocol_name = "ah"

        if pkt.haslayer(IP) and pkt[IP].proto == 50:
            ipsec_seen = True
            esp_count += 1
            pkt_protocols.append("esp")
            protocol_name = "esp"
        if pkt.haslayer(IPv6) and pkt[IPv6].nxt == 50:
            ipsec_seen = True
            esp_count += 1
            pkt_protocols.append("esp")
            protocol_name = "esp"
        if pkt.haslayer(IP) and pkt[IP].proto == 51:
            ipsec_seen = True
            ah_count += 1
            pkt_protocols.append("ah")
            protocol_name = "ah"
        if pkt.haslayer(IPv6) and pkt[IPv6].nxt == 51:
            ipsec_seen = True
            ah_count += 1
            pkt_protocols.append("ah")
            protocol_name = "ah"

        if pkt_protocols:
            protocols.extend(pkt_protocols)

        spi_value = None
        seq_value = None
        if pkt.haslayer(ESP):
            spi_value = getattr(pkt[ESP], "spi", None)
            seq_value = getattr(pkt[ESP], "seq", None)
        elif pkt.haslayer(AH):
            spi_value = getattr(pkt[AH], "spi", None)
            seq_value = getattr(pkt[AH], "seq", None)

        obs = PacketObservation(
            index=idx,
            timestamp=_obs(float(pkt.time), "observed" if hasattr(pkt, "time") else "unavailable"),
            src_ip=_obs(src_ip, "observed" if src_ip else "unavailable"),
            dst_ip=_obs(dst_ip, "observed" if dst_ip else "unavailable"),
            src_port=_obs(getattr(pkt[UDP], "sport", None) if pkt.haslayer(UDP) else None, "observed" if pkt.haslayer(UDP) else "unavailable"),
            dst_port=_obs(getattr(pkt[UDP], "dport", None) if pkt.haslayer(UDP) else None, "observed" if pkt.haslayer(UDP) else "unavailable"),
            protocol=_obs(protocol_name, "observed" if protocol_name != "unknown" else "unavailable"),
            length=_obs(length, "observed"),
            spi=_obs(spi_value, "observed" if spi_value is not None else "unavailable"),
            sequence=_obs(seq_value, "observed" if seq_value is not None else "unavailable"),
            ike_version=_obs(ike_version if ike_seen else None, "observed" if ike_seen else "unavailable"),
            ipsec_type=_obs(
                ",".join(sorted(set(pkt_protocols))) if pkt_protocols else None,
                "observed" if pkt_protocols else "unavailable",
            ),
        )
        per_packet.append(obs)

    if not packets:
        return IPsecAnalysisResult(
            file_path=str(pcap_path),
            ipsec_detected=_obs(None, "unavailable", "No packets were available for analysis."),
            ike_detected=_obs(None, "unavailable", "No IKE packets were observed."),
            ike_version=_obs(None, "unavailable", "IKE version cannot be derived without IKE traffic."),
            ipsec_protocols=_obs([], "unavailable", "No IPsec protocol headers were detected."),
            esp_packets=_obs(0, "observed" if esp_count else "unavailable"),
            ah_packets=_obs(0, "observed" if ah_count else "unavailable"),
            packet_summary=PacketSummary(
                packet_count=_obs(0, "observed"),
                byte_count=_obs(0, "observed"),
                first_timestamp=_obs(None, "unavailable"),
                last_timestamp=_obs(None, "unavailable"),
                duration_seconds=_obs(0.0, "unavailable"),
            ),
            packet_size_statistics=PacketSizeStatistics(
                min_length=_obs(None, "unavailable"),
                max_length=_obs(None, "unavailable"),
                mean_length=_obs(None, "unavailable"),
                median_length=_obs(None, "unavailable"),
                stddev_length=_obs(None, "unavailable"),
            ),
            inter_arrival_times=_obs([], "unavailable"),
            flow_summary=FlowSummary(),
            packets=[],
        )

    durations = []
    if len(times) >= 2:
        for current, nxt in zip(times, times[1:]):
            durations.append(max(0.0, float(nxt) - float(current)))

    mean_len = float(sum(packet_lengths) / len(packet_lengths)) if packet_lengths else 0.0
    median_len = float(statistics.median(packet_lengths)) if packet_lengths else 0.0
    stddev_len = float(statistics.pstdev(packet_lengths)) if len(packet_lengths) > 1 else 0.0

    first_ts = min(times) if times else None
    last_ts = max(times) if times else None
    duration = (last_ts - first_ts) if first_ts is not None and last_ts is not None else 0.0

    unique_protocols = sorted(set(protocols))
    flow_src_ip = None
    flow_dst_ip = None
    if seen_ip_packets:
        flow_src_ip = seen_ip_packets[0][0]
        flow_dst_ip = seen_ip_packets[0][1]

    result = IPsecAnalysisResult(
        file_path=str(pcap_path),
        ipsec_detected=_obs(bool(ipsec_seen), "observed" if ipsec_seen else "unavailable", "ESP/AH headers were detected." if ipsec_seen else "No ESP/AH packets were observed."),
        ike_detected=_obs(bool(ike_seen), "observed" if ike_seen else "unavailable", "IKE traffic was detected on UDP/500 or UDP/4500." if ike_seen else "No IKE traffic was detected."),
        ike_version=_obs(ike_version, "observed" if ike_seen else "unavailable", "IKE version is inferred from IKE ports when present." if ike_seen else "IKE version could not be observed from the capture."),
        ipsec_protocols=_obs(unique_protocols, "observed" if unique_protocols else "unavailable", "Observed IPsec-related protocol names in the capture."),
        esp_packets=_obs(esp_count, "observed" if esp_count else "unavailable"),
        ah_packets=_obs(ah_count, "observed" if ah_count else "unavailable"),
        packet_summary=PacketSummary(
            packet_count=_obs(len(packets), "observed"),
            byte_count=_obs(packet_total_bytes, "observed"),
            first_timestamp=_obs(first_ts, "observed" if first_ts is not None else "unavailable"),
            last_timestamp=_obs(last_ts, "observed" if last_ts is not None else "unavailable"),
            duration_seconds=_obs(duration, "observed" if duration is not None else "unavailable"),
        ),
        packet_size_statistics=PacketSizeStatistics(
            min_length=_obs(min(packet_lengths), "observed" if packet_lengths else "unavailable"),
            max_length=_obs(max(packet_lengths), "observed" if packet_lengths else "unavailable"),
            mean_length=_obs(mean_len, "observed" if packet_lengths else "unavailable"),
            median_length=_obs(median_len, "observed" if packet_lengths else "unavailable"),
            stddev_length=_obs(stddev_len, "observed" if len(packet_lengths) > 1 else "unavailable"),
        ),
        inter_arrival_times=_obs(durations, "observed" if durations else "unavailable"),
        flow_summary=FlowSummary(
            src_ip=_obs(flow_src_ip, "observed" if flow_src_ip else "unavailable"),
            dst_ip=_obs(flow_dst_ip, "observed" if flow_dst_ip else "unavailable"),
            flow_direction=_obs("forward" if flow_src_ip and flow_dst_ip else None, "inferred" if flow_src_ip and flow_dst_ip else "unavailable"),
            total_packets=_obs(len(packets), "observed"),
            total_bytes=_obs(packet_total_bytes, "observed"),
            duration_seconds=_obs(duration, "observed" if duration is not None else "unavailable"),
        ),
        packets=per_packet,
    )
    return result


def analyze_pcap_path(path: str | Path) -> Dict[str, Any]:
    return json.loads(analyze_pcap(path).model_dump_json())
