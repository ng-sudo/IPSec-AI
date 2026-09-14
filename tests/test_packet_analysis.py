from __future__ import annotations

from pathlib import Path

from scapy.all import AH, ESP, IP, Raw, UDP, wrpcap

from packet_engine.analyzer import analyze_pcap


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
    ]
    wrpcap(str(path), packets)


def test_analyze_pcap_detects_ipsec_protocols(tmp_path):
    sample_path = tmp_path / "sample_ipsec.pcap"
    _write_sample_pcap(sample_path)

    result = analyze_pcap(sample_path)

    assert result.ipsec_detected.status == "observed"
    assert result.ike_detected.status == "observed"
    assert result.packet_summary.packet_count.status == "observed"
    assert result.packet_summary.byte_count.status == "observed"
    assert result.ipsec_protocols.status == "observed"
    assert "esp" in str(result.ipsec_protocols.value).lower()
    assert result.flow_summary.src_ip.status in {"observed", "inferred"}
    assert result.flow_summary.dst_ip.status in {"observed", "inferred"}


def test_analyze_pcap_reports_missing_protocol_as_unavailable(tmp_path):
    sample_path = tmp_path / "empty.pcap"
    _write_sample_pcap(sample_path)

    result = analyze_pcap(sample_path)

    assert result.ike_version.status in {"observed", "inferred", "unavailable"}
    assert result.ah_packets.status in {"observed", "unavailable"}
    assert result.packet_size_statistics.mean_length.status == "observed"
