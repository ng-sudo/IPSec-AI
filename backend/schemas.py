from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

from packet_engine.features import FeatureExtractionResult
from packet_engine.models import IPsecAnalysisResult, Observation
from risk_engine.models import RiskAssessment
from security_engine.models import SecurityAssessment


class UploadResponse(BaseModel):
    capture_id: str
    filename: str
    size_bytes: int
    content_type: Optional[str] = None


class CaptureInfo(BaseModel):
    capture_id: str
    filename: str
    size_bytes: int


class AnalysisRequest(BaseModel):
    vpn_configuration: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PredictionResponse(BaseModel):
    predicted_traffic_type: Observation
    confidence: Observation
    model_version: Observation


class MetadataInference(BaseModel):
    ipsec_detected: Observation
    ike_version: Observation
    source_ip: Observation
    destination_ip: Observation
    flow_direction: Observation
    encrypted_payload_contents: Observation


class CompleteAnalysisResponse(BaseModel):
    capture_id: str
    vpn_configuration: Dict[str, Any]
    packet_analysis: IPsecAnalysisResult
    features: FeatureExtractionResult
    prediction: PredictionResponse
    security_assessment: SecurityAssessment
    risk_assessment: RiskAssessment
    metadata_inference: MetadataInference


class ErrorResponse(BaseModel):
    detail: str


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    classifier_available: bool
