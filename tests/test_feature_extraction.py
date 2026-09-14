from __future__ import annotations

from pathlib import Path

from scapy.all import AH, ESP, IP, Raw, UDP, wrpcap

from packet_engine.features import extract_features_from_pcap


def _write_sample_pcap(path: Path) -> None:
    packets = [
        IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=500, dport=500)
        / Raw(load=b"\x00\x00\x00\x00IKE"),
        IP(src="10.0.0.1", dst="10.0.0.2", proto=50)
        / ESP(spi=0x11111111, seq=1)
        / Raw(load=b"encrypted-payload-1"),
        IP(src="10.0.0.2", dst="10.0.0.1", proto=51)
        / AH(spi=0x22222222, seq=2)
        / Raw(load=b"ah-payload"),
        IP(src="10.0.0.1", dst="10.0.0.2", proto=50)
        / ESP(spi=0x33333333, seq=3)
        / Raw(load=b"encrypted-payload-2"),
    ]
    wrpcap(str(path), packets)


def test_extract_features_from_pcap_creates_reproducible_vector(tmp_path):
    pcap_path = tmp_path / "sample_feature_capture.pcap"
    _write_sample_pcap(pcap_path)

    result = extract_features_from_pcap(pcap_path)

    assert result.raw_packet_info.packet_count.status == "observed"
    assert result.deterministic_protocol_info.ipsec_detected.status == "observed"
    assert result.deterministic_protocol_info.ike_detected.status == "observed"
    assert result.derived_flow_features.packet_count.status == "observed"
    assert result.derived_flow_features.packet_size_min.status == "observed"
    assert result.derived_flow_features.packet_size_mean.status == "observed"
    assert result.derived_flow_features.inter_arrival_mean.status in {"observed", "unavailable"}
    assert result.derived_flow_features.directionality.status in {"inferred", "unavailable"}
    assert len(result.ml_features.features) > 0
    assert result.ml_features.preprocessing.version == "1.0"


def test_extract_features_preserves_unavailable_when_no_information(tmp_path):
    pcap_path = tmp_path / "empty_feature_capture.pcap"
    _write_sample_pcap(pcap_path)

    result = extract_features_from_pcap(pcap_path)
    assert result.deterministic_protocol_info.protocol_names.status in {"observed", "unavailable"}
    assert result.derived_flow_features.bytes_per_second.status in {"observed", "unavailable"}
    assert result.ml_features.preprocessing.payload_exclusion == "encrypted_payload_contents_excluded"
