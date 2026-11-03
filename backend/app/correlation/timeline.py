"""Timeline construction — sort, group, and annotate signals chronologically."""

from __future__ import annotations

import uuid
from collections import Counter
from datetime import timedelta
from typing import Any

from app.core.logging import get_logger
from app.schemas.incidents import (
    CorrelationMethod,
    ErrorOnset,
    RawSignal,
    SignalKind,
    SignalSeverity,
    SignalSource,
    TimelineEvent,
)
from .signals import is_deployment_signal

logger = get_logger(__name__)

# Severity ordering (higher index = more severe)
_SEV_ORDER = {
    SignalSeverity.INFO: 0,
    SignalSeverity.LOW: 1,
    SignalSeverity.MEDIUM: 2,
    SignalSeverity.HIGH: 3,
    SignalSeverity.CRITICAL: 4,
}

ERROR_SEVERITIES = frozenset({SignalSeverity.HIGH, SignalSeverity.CRITICAL, SignalSeverity.MEDIUM})


def build_timeline(signals: list[RawSignal]) -> list[TimelineEvent]:
    """Convert normalized signals into a chronological timeline.

    Signals are sorted by timestamp.  Signals within the same 30-second
    bucket that share a service_name are merged into a single entry to
    reduce noise while preserving all signal IDs for traceability.
    """
    if not signals:
        return []

    sorted_signals = sorted(signals, key=lambda s: s.timestamp)

    # Bucket by (30-second window, service_name, kind)
    buckets: dict[tuple[Any, ...], list[RawSignal]] = {}
    for sig in sorted_signals:
        bucket_ts = sig.timestamp.replace(
            second=(sig.timestamp.second // 30) * 30, microsecond=0
        )
        key = (bucket_ts, sig.service_name, sig.kind)
        buckets.setdefault(key, []).append(sig)

    events: list[TimelineEvent] = []
    for (bucket_ts, service_name, kind), bucket_signals in sorted(
        buckets.items(), key=lambda x: x[0][0]
    ):
        representative = bucket_signals[0]
        is_deploy = is_deployment_signal(kind, representative.message)

        # Determine correlation methods present in this bucket
        methods: list[CorrelationMethod] = []
        if any(s.trace_id for s in bucket_signals):
            methods.append(CorrelationMethod.TRACE_ID)
        if any(s.request_id for s in bucket_signals):
            methods.append(CorrelationMethod.REQUEST_ID)
        if any(s.deployment_version for s in bucket_signals):
            methods.append(CorrelationMethod.DEPLOYMENT_VERSION)
        if not methods:
            methods.append(CorrelationMethod.TEMPORAL_PROXIMITY)

        # Build a concise description
        count = len(bucket_signals)
        suffix = f" (×{count})" if count > 1 else ""
        description = _describe_signal(representative) + suffix

        events.append(
            TimelineEvent(
                event_id=str(uuid.uuid4())[:8],
                timestamp=bucket_ts,
                source=representative.source,
                kind=kind,
                severity=representative.severity,
                service_name=service_name,
                description=description,
                is_deployment=is_deploy,
                correlation_methods=methods,
                evidence_ptr=representative.evidence_ptr,
                signal_ids=[s.signal_id for s in bucket_signals],
            )
        )

    return events


def _describe_signal(sig: RawSignal) -> str:
    """Build a human-readable one-line description for a signal."""
    kind_labels: dict[SignalKind, str] = {
        SignalKind.ECS_TASK_FAILURE: "ECS task failed",
        SignalKind.ECS_DEPLOYMENT_EVENT: "ECS deployment",
        SignalKind.ECS_SERVICE_DEGRADED: "ECS service degraded",
        SignalKind.EKS_POD_RESTART: "EKS pod restarted",
        SignalKind.EKS_APP_LOG_ERROR: "EKS application error",
        SignalKind.EKS_OOM_KILLED: "EKS pod OOM-killed",
        SignalKind.EC2_METRIC_ANOMALY: "EC2 metric anomaly",
        SignalKind.EC2_STATUS_CHECK_FAILURE: "EC2 status check failed",
        SignalKind.LAMBDA_INVOCATION_FAILURE: "Lambda invocation failed",
        SignalKind.LAMBDA_TIMEOUT: "Lambda timeout",
        SignalKind.LAMBDA_ERROR_RATE: "Lambda error rate elevated",
        SignalKind.LAMBDA_THROTTLE: "Lambda throttled",
        SignalKind.ALB_TARGET_5XX: "ALB target 5xx errors",
        SignalKind.ALB_HIGH_LATENCY: "ALB high latency",
        SignalKind.ALB_UNHEALTHY_HOSTS: "ALB unhealthy hosts",
        SignalKind.RDS_CONNECTION_ERROR: "RDS connection error",
        SignalKind.RDS_HIGH_CPU: "RDS CPU elevated",
        SignalKind.RDS_AVAILABILITY_EVENT: "RDS availability event",
        SignalKind.RDS_MAX_CONNECTIONS: "RDS max connections reached",
        SignalKind.RDS_REPLICATION_LAG: "RDS replication lag",
        SignalKind.ALARM_TRIGGERED: "CloudWatch alarm triggered",
        SignalKind.ALARM_RESOLVED: "CloudWatch alarm resolved",
        SignalKind.LOG_ERROR: "Log error",
        SignalKind.METRIC_SPIKE: "Metric spike",
    }
    base = kind_labels.get(sig.kind, str(sig.kind))
    if sig.metric_name and sig.metric_value is not None:
        base += f" — {sig.metric_name}={sig.metric_value:.1f}{sig.metric_unit or ''}"
    elif sig.message:
        truncated = sig.message[:120]
        base += f": {truncated}"
    return base


def compute_error_onset(signals: list[RawSignal]) -> ErrorOnset | None:
    """Find when errors first appeared and how quickly they ramped up.

    Uses a 5-minute sliding window to measure onset rate.
    Returns None if there are no error-severity signals.
    """
    error_signals = [
        s for s in signals if s.severity in ERROR_SEVERITIES
        and s.kind not in {SignalKind.ALARM_RESOLVED}
    ]
    if not error_signals:
        return None

    error_signals.sort(key=lambda s: s.timestamp)
    first = error_signals[0]
    onset_window = timedelta(minutes=5)

    # Count errors in the first 5-min window after first error
    onset_end = first.timestamp + onset_window
    onset_errors = [s for s in error_signals if s.timestamp <= onset_end]
    onset_rate = len(onset_errors) / 5.0  # per minute

    # Find peak: sliding 5-min window with max count
    peak_count = 0
    peak_ts = first.timestamp
    for i, sig in enumerate(error_signals):
        window_end = sig.timestamp + onset_window
        window_errors = sum(1 for s in error_signals if sig.timestamp <= s.timestamp <= window_end)
        if window_errors > peak_count:
            peak_count = window_errors
            peak_ts = sig.timestamp

    peak_rate = peak_count / 5.0

    # Time from first error to peak
    time_to_peak = (peak_ts - first.timestamp).total_seconds() / 60.0

    error_kind_counts = Counter(s.kind for s in error_signals)
    top_kinds = [str(k) for k, _ in error_kind_counts.most_common(5)]

    affected_services = sorted({s.service_name for s in error_signals})

    return ErrorOnset(
        first_error_at=first.timestamp,
        first_error_signal_id=first.signal_id,
        onset_rate_per_minute=onset_rate,
        peak_rate_per_minute=peak_rate,
        peak_at=peak_ts,
        error_kinds=top_kinds,
        affected_services=affected_services,
        time_to_peak_minutes=time_to_peak,
    )
