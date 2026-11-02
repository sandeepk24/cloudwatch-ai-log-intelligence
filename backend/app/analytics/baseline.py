"""Time bucketing and baseline statistics helpers.

These are the lowest-level building blocks for every other module in
`app.analytics`: turning a flat list of timestamped events into fixed-size
time buckets (for trend/anomaly analysis) or equal-length historical
periods (for recurring-pattern analysis), plus small, dependency-free
statistics helpers.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any


@dataclass
class TimeBucket:
    """Aggregate counts for a fixed time window."""

    start: datetime
    end: datetime
    count: int = 0
    error_count: int = 0
    warn_count: int = 0


@dataclass
class HistoryPeriod:
    """A span of raw events representing one historical period (e.g. "1 day
    ago", "2 days ago", ...) used for recurring-pattern analysis."""

    start: datetime
    end: datetime
    events: list[dict[str, Any]] = field(default_factory=list)


def _bucket_index(
    ts: datetime,
    range_start: datetime,
    bucket_delta: timedelta,
    num_buckets: int,
) -> int | None:
    """Return the bucket index for a timestamp, or None if it falls before
    range_start. Timestamps at/after the final bucket boundary are clamped
    into the last bucket so boundary events are never silently dropped."""
    if ts < range_start:
        return None
    offset_seconds = (ts - range_start).total_seconds()
    bucket_seconds = bucket_delta.total_seconds()
    if bucket_seconds <= 0:
        return None
    idx = int(offset_seconds // bucket_seconds)
    if idx < 0:
        return None
    if idx >= num_buckets:
        idx = num_buckets - 1
    return idx


def bucketize(
    events: list[dict[str, Any]],
    range_start: datetime,
    range_end: datetime,
    bucket_minutes: int,
) -> list[TimeBucket]:
    """Split [range_start, range_end) into fixed-size buckets and count
    events (by severity) per bucket.

    Each event dict must have a ``timestamp`` key (datetime) and may have a
    ``severity`` key (one of "ERROR"/"WARN"/...). Buckets with zero events
    are included rather than skipped, so gaps in traffic are visible and do
    not silently bias baseline statistics (a missing bucket is very
    different from a bucket we know had zero events).
    """
    if bucket_minutes <= 0:
        raise ValueError("bucket_minutes must be positive")
    if range_end <= range_start:
        return []

    bucket_delta = timedelta(minutes=bucket_minutes)
    num_buckets = max(1, int((range_end - range_start) / bucket_delta))

    buckets: list[TimeBucket] = []
    cursor = range_start
    for _ in range(num_buckets):
        bucket_end = min(cursor + bucket_delta, range_end)
        buckets.append(TimeBucket(start=cursor, end=bucket_end))
        cursor = bucket_end

    for event in events:
        ts = event["timestamp"]
        idx = _bucket_index(ts, range_start, bucket_delta, len(buckets))
        if idx is None:
            continue
        bucket = buckets[idx]
        bucket.count += 1
        severity = event.get("severity")
        if severity == "ERROR":
            bucket.error_count += 1
        elif severity == "WARN":
            bucket.warn_count += 1

    return buckets


def partition_into_periods(
    events: list[dict[str, Any]],
    range_start: datetime,
    range_end: datetime,
    period_minutes: int,
) -> list[HistoryPeriod]:
    """Split [range_start, range_end) into equal-length periods (oldest
    first) and assign raw events to each, for recurring-pattern /
    historical-frequency analysis where the full event payload (not just a
    count) is needed per period.
    """
    if period_minutes <= 0:
        raise ValueError("period_minutes must be positive")
    if range_end <= range_start:
        return []

    period_delta = timedelta(minutes=period_minutes)
    num_periods = max(1, int((range_end - range_start) / period_delta))

    periods: list[HistoryPeriod] = []
    cursor = range_start
    for _ in range(num_periods):
        period_end = min(cursor + period_delta, range_end)
        periods.append(HistoryPeriod(start=cursor, end=period_end))
        cursor = period_end

    for event in events:
        ts = event["timestamp"]
        idx = _bucket_index(ts, range_start, period_delta, len(periods))
        if idx is None:
            continue
        periods[idx].events.append(event)

    return periods


def mean_stddev(values: list[float]) -> tuple[float, float]:
    """Return (mean, sample standard deviation). stddev is 0.0 for fewer
    than 2 points (there is no variance to report)."""
    if not values:
        return 0.0, 0.0
    mean = statistics.fmean(values)
    if len(values) < 2:
        return mean, 0.0
    return mean, statistics.stdev(values)


def has_sufficient_history(num_points: int, min_points: int) -> bool:
    """Explicit, named check for "do we have enough historical data points
    to run a statistical comparison" -- used to decide whether a result
    should carry AnalysisStatus.INSUFFICIENT_DATA."""
    return num_points >= min_points
