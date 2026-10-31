"""API endpoints for Log Intelligence Engine."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status

from app.core.logging import get_logger
from app.core.responses import fail, ok
from app.intelligence.engine import LogIntelligenceEngine
from app.schemas.common import Envelope
from app.schemas.intelligence import (
    AnalyzeEventsRequest,
    AnalyzeEventsResponse,
    ClassifyEventRequest,
    ClassifyEventResponse,
    IntelligenceSummary,
)

logger = get_logger(__name__)
router = APIRouter(prefix="/intelligence", tags=["intelligence"])


def _get_engine() -> LogIntelligenceEngine:
    """Get or create the intelligence engine instance."""
    return LogIntelligenceEngine(redact_pii=True)


@router.post(
    "/classify",
    response_model=Envelope[ClassifyEventResponse],
    summary="Classify a single log event",
    description="Classify severity, detect patterns, and extract context from a single log message.",
)
async def classify_event(
    body: ClassifyEventRequest,
    request: Request,
) -> Envelope[ClassifyEventResponse]:
    """Classify a single log event."""
    try:
        engine = _get_engine()

        event = engine.classify_event(
            message=body.message,
            timestamp=body.timestamp or datetime.now(UTC),
            log_group=body.log_group,
            log_stream=body.log_stream,
            raw_fields=body.raw_fields if body.raw_fields else None,
        )

        return ok(ClassifyEventResponse(event=event), request)

    except Exception as e:
        logger.exception("Failed to classify event")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=fail(
                "classification_error",
                f"Classification failed: {e!s}",
                request,
            ).model_dump(mode="json"),
        ) from e


@router.post(
    "/analyze",
    response_model=Envelope[AnalyzeEventsResponse],
    summary="Analyze batch of log events",
    description="Analyze multiple log events: classify, detect patterns, deduplicate, cluster failures, and calculate metrics.",
)
async def analyze_events(
    body: AnalyzeEventsRequest,
    request: Request,
) -> Envelope[AnalyzeEventsResponse]:
    """Analyze a batch of log events."""
    try:
        engine = _get_engine()

        summary = engine.analyze_events(
            events=body.events,
            baseline_events=body.baseline_events,
            include_samples=body.include_samples,
            max_samples=body.max_samples,
            top_failures_count=body.top_failures_count,
        )

        return ok(AnalyzeEventsResponse(summary=summary), request)

    except Exception as e:
        logger.exception("Failed to analyze events")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=fail(
                "analysis_error",
                f"Analysis failed: {e!s}",
                request,
            ).model_dump(mode="json"),
        ) from e


@router.post(
    "/summary",
    response_model=Envelope[IntelligenceSummary],
    summary="Generate intelligence summary",
    description="Generate a comprehensive intelligence summary from log events with clustering and metrics.",
)
async def generate_summary(
    events: list[dict[str, Any]],
    request: Request,
    baseline_events: list[dict[str, Any]] | None = None,
    top_failures_count: int = 10,
) -> Envelope[IntelligenceSummary]:
    """Generate an intelligence summary from events."""
    if not events:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=fail(
                "validation_error",
                "At least one event is required",
                request,
            ).model_dump(mode="json"),
        )

    try:
        engine = _get_engine()

        summary = engine.analyze_events(
            events=events,
            baseline_events=baseline_events,
            include_samples=True,
            max_samples=5,
            top_failures_count=top_failures_count,
        )

        return ok(summary, request)

    except Exception as e:
        logger.exception("Failed to generate summary")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=fail(
                "summary_error",
                f"Summary generation failed: {e!s}",
                request,
            ).model_dump(mode="json"),
        ) from e


@router.get(
    "/health",
    response_model=Envelope[dict[str, Any]],
    summary="Intelligence engine health",
    description="Check health and capabilities of the intelligence engine.",
)
async def health(request: Request) -> Envelope[dict[str, Any]]:
    """Check intelligence engine health."""
    return ok(
        {
            "status": "healthy",
            "capabilities": [
                "severity_classification",
                "pattern_detection",
                "context_extraction",
                "fingerprinting",
                "deduplication",
                "failure_clustering",
                "exception_grouping",
                "error_rate_calculation",
                "pii_redaction",
            ],
            "supported_patterns": [
                "java_exception",
                "python_traceback",
                "http_4xx",
                "http_5xx",
                "database_error",
                "connection_timeout",
                "oom",
                "throttling",
                "auth_failure",
                "permission_denied",
                "ssl_error",
                "dns_error",
                "disk_full",
                "circuit_breaker",
                "rate_limit",
            ],
        },
        request,
    )
