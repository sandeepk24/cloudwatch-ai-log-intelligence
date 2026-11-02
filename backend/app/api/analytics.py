"""CloudWatch anomaly and pattern analysis endpoints.

Mounted directly at `/api/analytics` (outside the versioned `/api/v1`
prefix used by the rest of this service) per product requirements for this
module:

  GET /api/analytics/patterns
  GET /api/analytics/anomalies
  GET /api/analytics/trends
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request, status

from app.core.logging import get_logger
from app.core.responses import fail, ok
from app.schemas.analytics import (
    AnomaliesResponse,
    AnomalyThresholds,
    PatternsResponse,
    TrendsResponse,
)
from app.schemas.common import Envelope
from app.schemas.logs import TimeRangePreset
from app.services.pattern_analysis import PatternAnalysisService

logger = get_logger(__name__)
router = APIRouter(prefix="/analytics")


def _get_service() -> PatternAnalysisService:
    return PatternAnalysisService()


def _require_log_groups(log_group: list[str], request: Request) -> list[str]:
    if not log_group:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=fail(
                "validation_error",
                "At least one `log_group` query parameter is required.",
                request,
            ).model_dump(mode="json"),
        )
    return log_group


@router.get(
    "/patterns",
    response_model=Envelope[PatternsResponse],
    summary="Cluster log lines into patterns and highlight newly-appearing ones",
)
async def get_patterns(
    request: Request,
    log_group: Annotated[list[str], Query(..., description="Log group name; repeat for multiple groups")],
    time_range: Annotated[TimeRangePreset, Query(description="Preset window for the current period")] = (
        TimeRangePreset.LAST_1_HOUR
    ),
    start_time: Annotated[datetime | None, Query(description="Custom window start (requires end_time)")] = None,
    end_time: Annotated[datetime | None, Query(description="Custom window end (requires start_time)")] = None,
    baseline_periods: Annotated[
        int,
        Query(
            ge=0,
            le=10,
            description="How many preceding windows of the same duration to use as the baseline. 0 disables new-pattern detection.",
        ),
    ] = 1,
    min_occurrences: Annotated[int, Query(ge=1, description="Drop patterns seen fewer than this many times")] = 1,
    prefer_native: Annotated[
        bool,
        Query(
            description="Attempt CloudWatch Logs Insights' native `pattern` command before falling back to local clustering"
        ),
    ] = False,
    account_alias: Annotated[str | None, Query(max_length=128)] = None,
) -> Envelope[PatternsResponse]:
    """Cluster log lines in the requested window into patterns, and -- when
    a baseline is available -- diff them against the preceding window(s) to
    surface newly-appearing, disappeared, increasing, and decreasing
    patterns.

    If the baseline window has no events, `status` is `insufficient_data`
    and `diff` is omitted rather than misleadingly reporting every pattern
    as "new".
    """
    _require_log_groups(log_group, request)
    service = _get_service()

    try:
        result = await service.get_patterns(
            log_group_names=log_group,
            time_range_preset=time_range,
            start_time=start_time,
            end_time=end_time,
            baseline_periods=baseline_periods,
            account_alias=account_alias,
            min_occurrences=min_occurrences,
            prefer_native=prefer_native,
        )
        return ok(result, request)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=fail("invalid_request", str(e), request).model_dump(mode="json"),
        ) from e
    except Exception as e:
        logger.exception("Pattern analysis failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=fail("pattern_analysis_error", str(e), request).model_dump(mode="json"),
        ) from e


@router.get(
    "/anomalies",
    response_model=Envelope[AnomaliesResponse],
    summary="Statistical anomaly detection across frequency, error rate, and optional metrics",
)
async def get_anomalies(
    request: Request,
    log_group: Annotated[list[str], Query(..., description="Log group name; repeat for multiple groups")],
    time_range: Annotated[TimeRangePreset, Query(description="Preset window for the current period")] = (
        TimeRangePreset.LAST_1_HOUR
    ),
    start_time: Annotated[datetime | None, Query(description="Custom window start (requires end_time)")] = None,
    end_time: Annotated[datetime | None, Query(description="Custom window end (requires start_time)")] = None,
    bucket_minutes: Annotated[int, Query(ge=1, le=1440, description="Time bucket width in minutes")] = 5,
    history_periods: Annotated[
        int,
        Query(ge=0, le=50, description="How many preceding windows (of the current window's duration) to use as baseline history"),
    ] = 6,
    z_score_watch: Annotated[float, Query(gt=0)] = 2.0,
    z_score_anomaly: Annotated[float, Query(gt=0)] = 3.0,
    min_history_points: Annotated[int, Query(ge=2)] = 5,
    min_absolute_count: Annotated[int, Query(ge=1)] = 3,
    min_consecutive_for_incident: Annotated[int, Query(ge=1)] = 2,
    recurring_min_periods: Annotated[int, Query(ge=2)] = 2,
    metric_namespace: Annotated[str | None, Query(description="CloudWatch metric namespace, e.g. AWS/ApplicationELB")] = None,
    metric_name: Annotated[str | None, Query(description="CloudWatch metric name, e.g. TargetResponseTime")] = None,
    account_alias: Annotated[str | None, Query(max_length=128)] = None,
) -> Envelope[AnomaliesResponse]:
    """Detect statistically anomalous log frequency, error rate, and
    (when `metric_namespace`/`metric_name` are supplied) resource/latency
    signals, with configurable z-score thresholds.

    A statistical anomaly is not automatically an incident: `is_incident`
    is only set for error-driven anomalies that persist across multiple
    consecutive buckets and clear `min_absolute_count`. Recurring WARN-level
    patterns are reported separately as `recurring_warnings` and are never
    treated as incidents, however frequently they occur.

    `status` is `insufficient_data` when fewer than `min_history_points`
    historical buckets are available before the current window.
    """
    _require_log_groups(log_group, request)
    thresholds = AnomalyThresholds(
        z_score_watch=z_score_watch,
        z_score_anomaly=z_score_anomaly,
        min_history_points=min_history_points,
        min_absolute_count=min_absolute_count,
        min_consecutive_for_incident=min_consecutive_for_incident,
    )
    service = _get_service()

    try:
        result = await service.get_anomalies(
            log_group_names=log_group,
            time_range_preset=time_range,
            start_time=start_time,
            end_time=end_time,
            bucket_minutes=bucket_minutes,
            history_periods=history_periods,
            thresholds=thresholds,
            metric_namespace=metric_namespace,
            metric_name=metric_name,
            account_alias=account_alias,
            recurring_min_periods=recurring_min_periods,
        )
        return ok(result, request)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=fail("invalid_request", str(e), request).model_dump(mode="json"),
        ) from e
    except Exception as e:
        logger.exception("Anomaly analysis failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=fail("anomaly_analysis_error", str(e), request).model_dump(mode="json"),
        ) from e


@router.get(
    "/trends",
    response_model=Envelope[TrendsResponse],
    summary="Frequency and error-rate trends over time, with spike detection",
)
async def get_trends(
    request: Request,
    log_group: Annotated[list[str], Query(..., description="Log group name; repeat for multiple groups")],
    time_range: Annotated[TimeRangePreset, Query(description="Preset window for the current period")] = (
        TimeRangePreset.LAST_24_HOURS
    ),
    start_time: Annotated[datetime | None, Query(description="Custom window start (requires end_time)")] = None,
    end_time: Annotated[datetime | None, Query(description="Custom window end (requires start_time)")] = None,
    bucket_minutes: Annotated[int, Query(ge=1, le=1440, description="Time bucket width in minutes")] = 15,
    history_periods: Annotated[
        int,
        Query(ge=0, le=50, description="How many preceding windows (of the current window's duration) to use for baseline comparison and spike detection"),
    ] = 3,
    z_score_watch: Annotated[float, Query(gt=0)] = 2.0,
    z_score_anomaly: Annotated[float, Query(gt=0)] = 3.0,
    min_history_points: Annotated[int, Query(ge=2)] = 5,
    min_absolute_count: Annotated[int, Query(ge=1)] = 3,
    recurring_min_periods: Annotated[int, Query(ge=2)] = 2,
    account_alias: Annotated[str | None, Query(max_length=128)] = None,
) -> Envelope[TrendsResponse]:
    """Return a time-bucketed frequency/error-rate trend for the requested
    window, plus a comparison against the preceding baseline window(s) and
    any detected frequency spikes.

    `status` is `insufficient_data` when no baseline window could be
    established (`history_periods=0` or an otherwise empty baseline), in
    which case `change_from_baseline_pct` is omitted rather than guessed.
    """
    _require_log_groups(log_group, request)
    thresholds = AnomalyThresholds(
        z_score_watch=z_score_watch,
        z_score_anomaly=z_score_anomaly,
        min_history_points=min_history_points,
        min_absolute_count=min_absolute_count,
    )
    service = _get_service()

    try:
        result = await service.get_trends(
            log_group_names=log_group,
            time_range_preset=time_range,
            start_time=start_time,
            end_time=end_time,
            bucket_minutes=bucket_minutes,
            history_periods=history_periods,
            thresholds=thresholds,
            recurring_min_periods=recurring_min_periods,
            account_alias=account_alias,
        )
        return ok(result, request)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=fail("invalid_request", str(e), request).model_dump(mode="json"),
        ) from e
    except Exception as e:
        logger.exception("Trend analysis failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=fail("trend_analysis_error", str(e), request).model_dump(mode="json"),
        ) from e
