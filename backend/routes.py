from __future__ import annotations

from fastapi import APIRouter, File, HTTPException, UploadFile, status

from .schemas import AnalysisRequest, CaptureInfo, CompleteAnalysisResponse, ErrorResponse, UploadResponse
from .services import AnalysisService, CaptureNotFoundError, InvalidCaptureError


def create_router(service: AnalysisService) -> APIRouter:
    router = APIRouter(prefix="/api/v1", tags=["IPSecAI analysis"])

    @router.post(
        "/captures",
        response_model=UploadResponse,
        status_code=status.HTTP_201_CREATED,
        responses={400: {"model": ErrorResponse}},
        summary="Upload a PCAP capture",
    )
    async def upload_capture(file: UploadFile = File(...)) -> UploadResponse:
        try:
            content = await file.read()
            return service.store.save(file.filename or "capture.pcap", content, file.content_type)
        except InvalidCaptureError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @router.get(
        "/captures",
        response_model=list[CaptureInfo],
        summary="List selectable PCAP captures",
    )
    async def list_captures() -> list[CaptureInfo]:
        return list(service.store.list())

    @router.post(
        "/captures/{capture_id}/analyze",
        response_model=CompleteAnalysisResponse,
        responses={404: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
        summary="Analyze a selected PCAP",
    )
    async def analyze_capture(capture_id: str, request: AnalysisRequest) -> CompleteAnalysisResponse:
        try:
            return service.analyze(capture_id, request)
        except CaptureNotFoundError as exc:
            raise HTTPException(status_code=404, detail=f"capture not found: {capture_id}") from exc
        except (ValueError, OSError) as exc:
            raise HTTPException(status_code=422, detail=f"capture analysis failed: {exc}") from exc

    return router
