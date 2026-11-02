"""Unusual latency / resource signal detection via CloudWatch Metrics.

Metrics support is optional and, in this project, partially unimplemented
in live mode (see `app.adapters.aws.metrics.BotoCloudWatchMetricsAdapter`).
This module always degrades *explicitly*:

- if a metric cannot be fetched at all, we return
  ``status=AnalysisStatus.UNAVAILABLE`` with an explanatory note
- if a metric is fetched but has too few datapoints to establish a
  baseline, we return ``status=AnalysisStatus.INSUFFICIENT_DATA``
- we never fabricate values when metrics are missing, and a missing metric
  never fails the surrounding pattern/anomaly analysis -- log-based signals
  are still returned.
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.adapters.aws.base import AdapterNotImplementedError, CloudWatchMetricsPort
from app.analytics.anomaly import AnomalyDetector
from app.analytics.severity import score_from_classification
from app.core.logging import get_logger
from app.schemas.analytics import (
    AnalysisStatus,
    AnomalyClassification,
    AnomalyResult,
    AnomalyThresholds,
    ResourceSignal,
)

logger = get_logger(__name__)


async def analyze_resource_signal(
    metrics: CloudWatchMetricsPort,
    namespace: str,
    metric_name: str,
    thresholds: AnomalyThresholds | None = None,
) -> ResourceSignal:
    """Fetch a metric's recent datapoints and look for an unusual latest
    value relative to the rest of the series.

    Never raises: any failure to reach metrics is captured in the returned
    ResourceSignal's ``status``/``notes`` so callers can continue serving
    log-based analysis regardless.
    """
    try:
        raw = await metrics.get_metric_data(metric_name, namespace)
    except AdapterNotImplementedError as e:
        logger.info("Resource metrics unavailable for %s/%s: %s", namespace, metric_name, e)
        return ResourceSignal(
            namespace=namespace,
            metric_name=metric_name,
            status=AnalysisStatus.UNAVAILABLE,
            notes=[f"Metrics not available: {e}"],
        )
    except Exception as e:
        logger.warning("Failed to fetch metric %s/%s: %s", namespace, metric_name, e)
        return ResourceSignal(
            namespace=namespace,
            metric_name=metric_name,
            status=AnalysisStatus.ERROR,
            notes=[f"Error fetching metric: {e}"],
        )

    values: list[float] = [float(v) for v in raw.get("values", [])]

    if len(values) < 2:
        return ResourceSignal(
            namespace=namespace,
            metric_name=metric_name,
            status=AnalysisStatus.INSUFFICIENT_DATA,
            notes=[
                f"Only {len(values)} datapoint(s) returned for {namespace}/{metric_name}; "
                "at least 2 are required to evaluate a trend."
            ],
        )

    detector = AnomalyDetector(thresholds)
    *history, latest = values
    evaluation = detector.evaluate_point(latest, history)

    if len(history) < detector.thresholds.min_history_points:
        return ResourceSignal(
            namespace=namespace,
            metric_name=metric_name,
            status=AnalysisStatus.INSUFFICIENT_DATA,
            notes=evaluation.explanation,
        )

    score, label = score_from_classification(evaluation.classification, evaluation.z_score)
    now = datetime.now(UTC)

    anomaly = AnomalyResult(
        metric_name=f"{namespace}/{metric_name}",
        bucket_start=now,
        bucket_end=now,
        observed_value=latest,
        baseline_mean=evaluation.baseline_mean,
        baseline_stddev=evaluation.baseline_stddev,
        z_score=evaluation.z_score,
        classification=evaluation.classification,
        severity_score=score,
        severity_label=label,
        explanation=evaluation.explanation,
        # Resource signals never declare an incident on their own; they are
        # advisory context alongside log-based anomaly/incident detection.
        is_incident=False,
    )

    return ResourceSignal(
        namespace=namespace,
        metric_name=metric_name,
        status=AnalysisStatus.OK,
        anomalies=[anomaly] if evaluation.classification != AnomalyClassification.NORMAL else [],
        notes=[],
    )
