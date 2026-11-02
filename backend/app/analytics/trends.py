"""Frequency trends, spike detection, and recurring-warning tracking.

Everything here is a pure function over already-bucketed/partitioned data
(see `app.analytics.baseline`), so it is fully deterministic and testable
with synthetic datasets with no AWS dependency.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Any

from app.analytics.anomaly import AnomalyDetector
from app.analytics.baseline import HistoryPeriod, TimeBucket
from app.intelligence.fingerprint import normalize_message
from app.schemas.analytics import AnomalyResult, AnomalyThresholds, RecurringWarning, TrendPoint
from app.schemas.intelligence import LogSeverity


def build_trend_points(buckets: list[TimeBucket]) -> list[TrendPoint]:
    """Convert raw count buckets into TrendPoint records with a normalized
    errors-per-minute rate (so points with different bucket widths, e.g. a
    truncated final bucket, remain comparable)."""
    points: list[TrendPoint] = []
    for bucket in buckets:
        duration_minutes = max((bucket.end - bucket.start).total_seconds() / 60, 1 / 60)
        points.append(
            TrendPoint(
                bucket_start=bucket.start,
                bucket_end=bucket.end,
                total_count=bucket.count,
                error_count=bucket.error_count,
                warn_count=bucket.warn_count,
                error_rate_per_minute=bucket.error_count / duration_minutes,
            )
        )
    return points


def _frequency_severity_hint(bucket: TimeBucket) -> LogSeverity | None:
    if bucket.error_count > 0:
        return LogSeverity.ERROR
    if bucket.warn_count > 0:
        return LogSeverity.WARN
    return None


def detect_frequency_spikes(
    buckets: list[TimeBucket],
    thresholds: AnomalyThresholds | None = None,
) -> list[AnomalyResult]:
    """Detect sudden increases in total log volume across time buckets,
    using a rolling baseline built from preceding buckets only."""
    detector = AnomalyDetector(thresholds)
    return detector.evaluate_series(
        buckets,
        metric_name="log_frequency",
        value_fn=lambda b: float(b.count),
        severity_fn=_frequency_severity_hint,
    )


def detect_error_rate_anomalies(
    buckets: list[TimeBucket],
    thresholds: AnomalyThresholds | None = None,
) -> list[AnomalyResult]:
    """Detect anomalous error counts per bucket vs. a rolling baseline."""
    detector = AnomalyDetector(thresholds)
    return detector.evaluate_series(
        buckets,
        metric_name="error_rate",
        value_fn=lambda b: float(b.error_count),
        severity_fn=lambda b: LogSeverity.ERROR if b.error_count > 0 else None,
    )


def compare_to_baseline_error_rate(
    current_buckets: list[TimeBucket],
    baseline_buckets: list[TimeBucket],
) -> tuple[float | None, float | None, float | None]:
    """Compare current-window error rate to a baseline window's error rate.

    Returns ``(current_epm, baseline_epm, pct_change)``. ``baseline_epm``
    and ``pct_change`` are ``None`` when no baseline buckets are supplied --
    this is the explicit "insufficient historical data" signal callers
    should check before trusting the comparison.
    """
    if not current_buckets:
        return None, None, None

    def epm(buckets: list[TimeBucket]) -> float:
        total_minutes = sum((b.end - b.start).total_seconds() / 60 for b in buckets)
        if total_minutes <= 0:
            return 0.0
        total_errors = sum(b.error_count for b in buckets)
        return total_errors / total_minutes

    current_epm = epm(current_buckets)

    if not baseline_buckets:
        return current_epm, None, None

    baseline_epm = epm(baseline_buckets)
    if baseline_epm == 0:
        pct_change = None if current_epm == 0 else float("inf")
    else:
        pct_change = ((current_epm - baseline_epm) / baseline_epm) * 100

    return current_epm, baseline_epm, pct_change


def find_recurring_warnings(
    historical_periods: list[HistoryPeriod],
    *,
    min_periods_seen: int = 2,
) -> list[RecurringWarning]:
    """Identify WARN-level patterns that recur across historical periods.

    Args:
        historical_periods: ordered list of periods (oldest first), each
            carrying the raw events observed in that period.
        min_periods_seen: minimum number of periods a pattern must appear in
            to be classified ``is_recurring=True`` (vs. a one-off blip that
            happened to appear once).

    Explicitly handles insufficient data: recurrence cannot be established
    from a single period, so fewer than 2 periods returns an empty list.
    Callers should surface this as AnalysisStatus.INSUFFICIENT_DATA rather
    than reporting "no recurring warnings found" as if it were a confident
    negative result.

    Recurring warnings are intentionally **not** anomalies or incidents --
    see `app.analytics.anomaly` module docstring. A warning recurring every
    period at a stable rate is known, tracked noise, not a new event.
    """
    if len(historical_periods) < 2:
        return []

    num_periods = len(historical_periods)
    occurrences: dict[str, list[int]] = defaultdict(lambda: [0] * num_periods)
    samples: dict[str, dict[str, Any]] = {}

    for period_idx, period in enumerate(historical_periods):
        for event in period.events:
            if event.get("severity") != LogSeverity.WARN.value:
                continue
            normalized = normalize_message(event.get("message", ""))
            occurrences[normalized][period_idx] += 1
            samples.setdefault(normalized, event)

    results: list[RecurringWarning] = []
    for normalized, counts in occurrences.items():
        periods_seen = sum(1 for c in counts if c > 0)
        pattern_id = hashlib.sha256(f"WARN|{normalized}".encode()).hexdigest()[:16]
        results.append(
            RecurringWarning(
                pattern_id=pattern_id,
                normalized_pattern=normalized,
                representative_message=samples[normalized].get("message", ""),
                occurrences_per_period=counts,
                periods_seen=periods_seen,
                periods_total=num_periods,
                historical_frequency=periods_seen / num_periods,
                is_recurring=periods_seen >= min_periods_seen,
            )
        )

    results.sort(key=lambda r: (r.is_recurring, r.periods_seen), reverse=True)
    return results
