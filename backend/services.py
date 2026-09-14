from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional

from fastapi import UploadFile

from ml_classifier.pipeline import ClassifierBundle, load_bundle, predict_flow_features
from packet_engine.analyzer import analyze_pcap
from packet_engine.features import extract_features_from_analysis
from packet_engine.models import Observation
from risk_engine import RiskScoringEngine
from security_engine import AssessmentContext, SecurityAssessmentEngine

from .schemas import (
    AnalysisRequest,
    CaptureInfo,
    CompleteAnalysisResponse,
    MetadataInference,
    PredictionResponse,
    UploadResponse,
)

ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}
MAX_UPLOAD_BYTES = 100 * 1024 * 1024


class CaptureNotFoundError(LookupError):
    pass


class InvalidCaptureError(ValueError):
    pass


class CaptureStore:
    """Small local capture store; replaceable by object storage later."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._captures: Dict[str, CaptureInfo] = {}
        self._discover_existing()

    def _discover_existing(self) -> None:
        for path in self.root.iterdir():
            if path.is_file() and path.suffix.lower() in ALLOWED_EXTENSIONS:
                capture_id = path.stem
                self._captures[capture_id] = CaptureInfo(
                    capture_id=capture_id,
                    filename=path.name,
                    size_bytes=path.stat().st_size,
                )

    def save(self, filename: str, content: bytes, content_type: str | None = None) -> UploadResponse:
        suffix = Path(filename or "capture.pcap").suffix.lower()
        if suffix not in ALLOWED_EXTENSIONS:
            raise InvalidCaptureError("only .pcap and .pcapng uploads are supported")
        if not content:
            raise InvalidCaptureError("the uploaded capture is empty")
        if len(content) > MAX_UPLOAD_BYTES:
            raise InvalidCaptureError("the uploaded capture exceeds the 100 MiB limit")
        capture_id = uuid.uuid4().hex
        stored_name = f"{capture_id}{suffix}"
        path = self.root / stored_name
        path.write_bytes(content)
        info = CaptureInfo(capture_id=capture_id, filename=filename, size_bytes=len(content))
        self._captures[capture_id] = info
        return UploadResponse(capture_id=capture_id, filename=filename, size_bytes=len(content), content_type=content_type)

    def list(self) -> Iterable[CaptureInfo]:
        return sorted(self._captures.values(), key=lambda item: item.capture_id)

    def path_for(self, capture_id: str) -> Path:
        info = self._captures.get(capture_id)
        if info is None:
            raise CaptureNotFoundError(capture_id)
        path = self.root / f"{capture_id}{Path(info.filename).suffix.lower()}"
        if not path.is_file():
            raise CaptureNotFoundError(capture_id)
        return path


class AnalysisService:
    """Orchestrates existing analysis layers without embedding their logic in routes."""

    def __init__(self, store: CaptureStore, classifier: ClassifierBundle | None = None):
        self.store = store
        self.classifier = classifier
        self.security_engine = SecurityAssessmentEngine()
        self.risk_engine = RiskScoringEngine()

    def analyze(self, capture_id: str, request: AnalysisRequest) -> CompleteAnalysisResponse:
        pcap_path = self.store.path_for(capture_id)
        packet_analysis = analyze_pcap(pcap_path)
        features = extract_features_from_analysis(packet_analysis)
        protocol_metadata = {
            "ipsec_detected": packet_analysis.ipsec_detected.model_dump(),
            "ike_detected": packet_analysis.ike_detected.model_dump(),
            "ike_version": packet_analysis.ike_version.model_dump(),
            "protocol_names": features.deterministic_protocol_info.protocol_names.model_dump(),
            "esp_packets": packet_analysis.esp_packets.model_dump(),
            "ah_packets": packet_analysis.ah_packets.model_dump(),
        }
        flow_features = features.derived_flow_features.model_dump()
        prediction = self._predict({
            name: value.get("value") if isinstance(value, Mapping) and "value" in value else value
            for name, value in flow_features.items()
        })
        security_assessment = self.security_engine.assess(
            AssessmentContext.from_mappings(request.vpn_configuration, protocol_metadata, flow_features)
        )
        risk_assessment = self.risk_engine.score(security_assessment)
        metadata = MetadataInference(
            ipsec_detected=packet_analysis.ipsec_detected,
            ike_version=packet_analysis.ike_version,
            source_ip=packet_analysis.flow_summary.src_ip,
            destination_ip=packet_analysis.flow_summary.dst_ip,
            flow_direction=packet_analysis.flow_summary.flow_direction,
            encrypted_payload_contents=Observation(
                status="unavailable",
                value=None,
                notes="Encrypted payload contents are intentionally not inspected.",
            ),
        )
        return CompleteAnalysisResponse(
            capture_id=capture_id,
            vpn_configuration=request.vpn_configuration,
            packet_analysis=packet_analysis,
            features=features,
            prediction=prediction,
            security_assessment=security_assessment,
            risk_assessment=risk_assessment,
            metadata_inference=metadata,
        )

    def _predict(self, flow_features: Dict[str, object]) -> PredictionResponse:
        if self.classifier is None:
            unavailable = Observation(status="unavailable", value=None, notes="No classifier bundle is configured.")
            return PredictionResponse(
                predicted_traffic_type=unavailable,
                confidence=unavailable,
                model_version=unavailable,
            )
        prediction = predict_flow_features(self.classifier, flow_features)
        return PredictionResponse(
            predicted_traffic_type=Observation(status="inferred", value=prediction.predicted_traffic_type),
            confidence=Observation(status="inferred", value=prediction.confidence),
            model_version=Observation(status="observed", value=prediction.model_version),
        )


def load_optional_classifier(model_path: str | Path | None) -> ClassifierBundle | None:
    if model_path is None:
        return None
    return load_bundle(model_path)
