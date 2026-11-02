"""Schemas for CloudWatch anomaly and pattern analysis.

These models back three read endpoints:
  GET /api/analytics/patterns   - pattern clustering + new-pattern diffing
  GET /api/analytics/anomalies  - statistical anomaly detection
  GET /api/analytics/trends     - frequency / error-rate trends over time
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from app.schemas.intelligence import LogSeverity

# -----------------------------------------------------------------------------
# Shared enums
# -----------------------------------------------------------------------------


class AnalysisStatus(StrEnum):
    """Overall status of an analysis response.

    OK                 - analysis ran with sufficient data for all requested signals
    PARTIAL            - some signals were computed, others were skipped (e.g. no
                          metric namespace supplied, or a baseline comparison was
                          skipped by choice)
    INSUFFICIENT_DATA  - there was not enough historical data to run statistical
                          comparisons; raw counts may still be present
    UNAVAILABLE        - the requested signal source (e.g. a CloudWatch metric or
                          native anomaly detector) could not be reached at all
    ERROR              - the signal could not be computed due to an error; see notes
    """

    OK = "ok"
    PARTIAL = "partial"
    INSUFFICIENT_DATA = "insufficient_data"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


class AnomalyClassification(StrEnum):
    """Classification of a statistical deviation.

    NORMAL    - within expected variance of the historical baseline
    WATCH     - mild deviation (>= watch threshold); informational only
    ANOMALY   - statistically significant deviation (>= anomaly threshold)
    INCIDENT  - an ANOMALY that *also* clears the incident-worthiness bar:
                error-driven, persists across multiple consecutive buckets,
                and clears the minimum absolute count. See
                `app.analytics.anomaly` for the full rationale.

    IMPORTANT: a statistical ANOMALY is not automatically an INCIDENT, and a
    WARN-level blip is never promoted to INCIDENT by this module.
    """

    NORMAL = "normal"
    WATCH = "watch"
    ANOMALY = "anomaly"
    INCIDENT = "incident"


class SeverityLabel(StrEnum):
    """Human-facing severity label. See `app.analytics.severity` for the
    documented scoring criteria that produce this label."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DataSource(StrEnum):
    """Where a pattern/anomaly result came from.

    CLOUDWATCH_NATIVE  - produced by CloudWatch Logs Insights' own `pattern`
                         command and/or the managed Log Anomaly Detection
                         feature (ListAnomalies / ListLogAnomalyDetectors).
    LOCAL_STATISTICAL  - produced by this module's own normalization +
                         z-score based computation. Used whenever the native
                         feature is unavailable, unpermitted, or not
                         requested.
    """

    CLOUDWATCH_NATIVE = "cloudwatch_native"
    LOCAL_STATISTICAL = "local_statistical"


# -----------------------------------------------------------------------------
# Configurable thresholds
# -----------------------------------------------------------------------------


class AnomalyThresholds(BaseModel):
    """Configurable thresholds for statistical anomaly detection.

    All thresholds are overridable per-request via query parameters so
    different log groups/services can be tuned independently without a
    deployment.
    """

    z_score_watch: float = Field(default=2.0, gt=0, description="z-score at/above which a point is 'watch'")
    z_score_anomaly: float = Field(
        default=3.0, gt=0, description="z-score at/above which a point is 'anomaly'"
    )
    min_history_points: int = Field(
        default=5, ge=2, description="minimum preceding data points required before scoring a point"
    )
    min_absolute_count: int = Field(
        default=3, ge=1, description="minimum observed count required to ever classify as ANOMALY"
    )
    min_consecutive_for_incident: int = Field(
        default=2, ge=1, description="consecutive anomalous buckets required to promote ANOMALY -> INCIDENT"
    )


# -----------------------------------------------------------------------------
# Patterns
# -----------------------------------------------------------------------------


class LogPattern(BaseModel):
    """A cluster of log lines that share the same normalized shape.

    Equivalent in spirit to a row returned by CloudWatch Logs Insights'
    `pattern` command (`@pattern`, `@sampleCount`, `@severityLabel`), but can
    also be produced locally via `app.analytics.patterns`.
    """

    pattern_id: str
    normalized_pattern: str
    severity: LogSeverity
    occurrence_count: int
    ratio: float = Field(ge=0, le=1, description="fraction of all events in the window matching this pattern")
    first_seen: datetime
    last_seen: datetime
    representative_message: str
    sample_log_group: str | None = None
    sample_ptr: str | None = None
    is_new: bool = Field(default=False, description="true if absent from the baseline window entirely")
    severity_score: float = Field(default=0.0, ge=0, le=100)
    severity_label: SeverityLabel = SeverityLabel.LOW


class PatternDiff(BaseModel):
    """Difference between a current window's patterns and a baseline window's
    patterns. Conceptually mirrors the CloudWatch console's pattern
    "Compare" view; CloudWatch Logs Insights has no literal `diff` query
    command, so this comparison is computed locally regardless of
    `data_source`.
    """

    new_patterns: list[LogPattern] = Field(default_factory=list)
    disappeared_patterns: list[LogPattern] = Field(default_factory=list)
    increased_patterns: list[LogPattern] = Field(default_factory=list)
    decreased_patterns: list[LogPattern] = Field(default_factory=list)
    change_ratio_threshold: float = 0.5


class PatternsResponse(BaseModel):
    """Response for GET /api/analytics/patterns."""

    status: AnalysisStatus
    data_source: DataSource
    time_range_start: datetime
    time_range_end: datetime
    total_events: int
    patterns: list[LogPattern]
    diff: PatternDiff | None = None
    notes: list[str] = Field(default_factory=list)


# -----------------------------------------------------------------------------
# Anomalies
# -----------------------------------------------------------------------------


class AnomalyResult(BaseModel):
    """A single statistically-evaluated data point."""

    metric_name: str
    bucket_start: datetime
    bucket_end: datetime
    observed_value: float
    baseline_mean: float | None = None
    baseline_stddev: float | None = None
    z_score: float | None = None
    classification: AnomalyClassification
    severity_score: float = Field(ge=0, le=100)
    severity_label: SeverityLabel
    explanation: list[str] = Field(default_factory=list)
    is_incident: bool = Field(
        default=False,
        description="True only when this anomaly also clears the incident-worthiness bar; see AnomalyClassification docs",
    )


class RecurringWarning(BaseModel):
    """A WARN-level pattern tracked across multiple historical periods.

    Recurring warnings are reported separately from anomalies/incidents:
    a warning recurring at a stable rate is "known noise", not a new
    incident, even though it may also independently trip a frequency
    anomaly in a given period.
    """

    pattern_id: str
    normalized_pattern: str
    representative_message: str
    occurrences_per_period: list[int]
    periods_seen: int
    periods_total: int
    historical_frequency: float = Field(ge=0, le=1)
    is_recurring: bool


class ResourceSignal(BaseModel):
    """Unusual latency/resource signal derived from a CloudWatch metric,
    when metrics are available for the target namespace/metric name."""

    namespace: str
    metric_name: str
    status: AnalysisStatus
    anomalies: list[AnomalyResult] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class AnomaliesResponse(BaseModel):
    """Response for GET /api/analytics/anomalies."""

    status: AnalysisStatus
    data_source: DataSource
    time_range_start: datetime
    time_range_end: datetime
    thresholds: AnomalyThresholds
    frequency_anomalies: list[AnomalyResult] = Field(default_factory=list)
    error_rate_anomalies: list[AnomalyResult] = Field(default_factory=list)
    recurring_warnings: list[RecurringWarning] = Field(default_factory=list)
    resource_signals: list[ResourceSignal] = Field(default_factory=list)
    incident_count: int = 0
    notes: list[str] = Field(default_factory=list)


# -----------------------------------------------------------------------------
# Trends
# -----------------------------------------------------------------------------


class TrendPoint(BaseModel):
    """A single time-bucketed point in a frequency/error-rate trend."""

    bucket_start: datetime
    bucket_end: datetime
    total_count: int
    error_count: int
    warn_count: int
    error_rate_per_minute: float


class TrendsResponse(BaseModel):
    """Response for GET /api/analytics/trends."""

    status: AnalysisStatus
    time_range_start: datetime
    time_range_end: datetime
    bucket_minutes: int
    points: list[TrendPoint]
    baseline_error_rate_per_minute: float | None = None
    current_error_rate_per_minute: float | None = None
    change_from_baseline_pct: float | None = None
    spikes: list[AnomalyResult] = Field(default_factory=list)
    recurring_warnings: list[RecurringWarning] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
