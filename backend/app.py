from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI

from .routes import create_router
from .schemas import HealthResponse
from .services import AnalysisService, CaptureStore, load_optional_classifier


def create_app(
    storage_dir: str | Path = "dataset/uploads",
    model_path: str | Path | None = None,
) -> FastAPI:
    model_path = model_path or os.getenv("IPSECAI_MODEL_PATH")
    store = CaptureStore(storage_dir)
    classifier = load_optional_classifier(model_path)
    service = AnalysisService(store, classifier)
    app = FastAPI(
        title="IPSecAI Analysis API",
        version="1.0.0",
        description="Structured PCAP analysis, encrypted-flow classification, deterministic security assessment, and project-specific risk scoring.",
    )
    app.state.analysis_service = service
    app.include_router(create_router(service))

    @app.get("/health", response_model=HealthResponse, tags=["system"], summary="Check API health")
    async def health() -> HealthResponse:
        return HealthResponse(classifier_available=service.classifier is not None)

    return app


app = create_app()
