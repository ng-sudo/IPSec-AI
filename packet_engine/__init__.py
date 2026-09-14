"""Packet analysis and feature extraction layer for PS 26160.

This package provides a standalone PCAP/PCAPNG parser for extracting observable
IPsec-related metadata and a reproducible feature-extraction pipeline for future
ML work. It intentionally does not classify traffic or infer values beyond what
is directly observable in the packet data.
"""

from .analyzer import analyze_pcap, analyze_pcap_path
from .features import extract_features_from_analysis, extract_features_from_pcap

__all__ = [
    "analyze_pcap",
    "analyze_pcap_path",
    "extract_features_from_analysis",
    "extract_features_from_pcap",
]
