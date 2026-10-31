"""Schemas for Log Intelligence Engine outputs."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# -----------------------------------------------------------------------------
# Log Severity
# -----------------------------------------------------------------------------


class LogSeverity(StrEnum):
    """Log severity levels."""

    ERROR = "ERROR"
    WARN = "WARN"
    INFO = "INFO"
    DEBUG = "DEBUG"
    TRACE = "TRACE"
    UNKNOWN = "UNKNOWN"


# -----------------------------------------------------------------------------
# Pattern Categories
# -----------------------------------------------------------------------------


class PatternCategory(StrEnum):
    """Categories of detected log patterns."""

    JAVA_EXCEPTION = "java_exception"
    PYTHON_TRACEBACK = "python_traceback"
    HTTP_CLIENT_ERROR = "http_4xx"
    HTTP_SERVER_ERROR = "http_5xx"
    DATABASE_ERROR = "database_error"
    CONNECTION_TIMEOUT = "connection_timeout"
    OUT_OF_MEMORY = "oom"
    THROTTLING = "throttling"
    AUTHENTICATION_FAILURE = "auth_failure"
    PERMISSION_DENIED = "permission_denied"
    RESOURCE_NOT_FOUND = "resource_not_found"
    VALIDATION_ERROR = "validation_error"
    CIRCUIT_BREAKER = "circuit_breaker"
    RATE_LIMIT = "rate_limit"
    DISK_FULL = "disk_full"
    SSL_ERROR = "ssl_error"
    DNS_ERROR = "dns_error"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


# -----------------------------------------------------------------------------
# Extracted Context
# -----------------------------------------------------------------------------


class ExtractedContext(BaseModel):
    """Context extracted from log messages."""

    request_id: str | None = None
    trace_id: str | None = None
    span_id: str | None = None
    correlation_id: str | None = None
    service_name: str | None = None
    deployment_version: str | None = None
    environment: str | None = None
    hostname: str | None = None
    pod_name: str | None = None
    container_id: str | None = None
    user_id: str | None = None  # Redacted if PII
    client_ip: str | None = None  # Redacted if configured
    http_method: str | None = None
    http_path: str | None = None
    http_status: int | None = None
    latency_ms: float | None = None
    error_code: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


# -----------------------------------------------------------------------------
# Pattern Detection
# -----------------------------------------------------------------------------


class DetectedPattern(BaseModel):
    """A pattern detected in a log event."""

    category: PatternCategory
    confidence: float = Field(ge=0.0, le=1.0)
    matched_rule: str
    matched_text: str | None = None
    is_false_positive: bool = False
    false_positive_reason: str | None = None


class ClassifiedEvent(BaseModel):
    """A log event with classification and extracted context."""

    original_message: str
    redacted_message: str
    severity: LogSeverity
    patterns: list[DetectedPattern] = Field(default_factory=list)
    context: ExtractedContext = Field(default_factory=ExtractedContext)
    fingerprint: str  # Normalized fingerprint for deduplication
    timestamp: datetime
    log_group: str
    log_stream: str | None = None
    ptr: str | None = None  # Link to original evidence


# -----------------------------------------------------------------------------
# Exception Grouping
# -----------------------------------------------------------------------------


class StackFrame(BaseModel):
    """A single frame in a stack trace."""

    file: str | None = None
    line: int | None = None
    function: str | None = None
    code: str | None = None


class ExceptionInfo(BaseModel):
    """Parsed exception information."""

    exception_type: str
    message: str
    stack_frames: list[StackFrame] = Field(default_factory=list)
    caused_by: ExceptionInfo | None = None


class ExceptionGroup(BaseModel):
    """A group of similar exceptions."""

    group_id: str
    exception_type: str
    message_pattern: str
    fingerprint: str
    occurrence_count: int
    first_seen: datetime
    last_seen: datetime
    representative_event: ClassifiedEvent
    sample_events: list[ClassifiedEvent] = Field(default_factory=list, max_length=5)
    affected_services: list[str] = Field(default_factory=list)
    affected_log_groups: list[str] = Field(default_factory=list)


# -----------------------------------------------------------------------------
# Failure Analysis
# -----------------------------------------------------------------------------


class FailureCluster(BaseModel):
    """A cluster of related failures."""

    cluster_id: str
    fingerprint: str
    category: PatternCategory
    severity: LogSeverity
    description: str
    occurrence_count: int
    first_seen: datetime
    last_seen: datetime
    errors_per_minute: float
    baseline_errors_per_minute: float | None = None
    change_from_baseline: float | None = None  # Percentage change
    is_anomaly: bool = False
    representative_event: ClassifiedEvent
    sample_events: list[ClassifiedEvent] = Field(default_factory=list, max_length=5)
    affected_services: list[str] = Field(default_factory=list)
    affected_log_groups: list[str] = Field(default_factory=list)
    evidence_links: list[str] = Field(default_factory=list)


class TopFailure(BaseModel):
    """A top recurring failure."""

    rank: int
    cluster: FailureCluster
    impact_score: float = Field(ge=0.0, le=1.0)


# -----------------------------------------------------------------------------
# Intelligence Summary
# -----------------------------------------------------------------------------


class SeverityDistribution(BaseModel):
    """Distribution of events by severity."""

    error_count: int = 0
    warn_count: int = 0
    info_count: int = 0
    debug_count: int = 0
    unknown_count: int = 0
    total_count: int = 0


class ErrorRateMetrics(BaseModel):
    """Error rate metrics."""

    errors_per_minute: float
    errors_per_hour: float
    baseline_errors_per_minute: float | None = None
    baseline_errors_per_hour: float | None = None
    change_percentage: float | None = None
    is_elevated: bool = False
    time_window_minutes: int


class IntelligenceSummary(BaseModel):
    """Complete intelligence summary for a set of log events."""

    summary_id: str
    generated_at: datetime
    time_range_start: datetime
    time_range_end: datetime
    total_events_analyzed: int
    total_events_after_dedup: int
    deduplication_ratio: float

    severity_distribution: SeverityDistribution
    error_rate: ErrorRateMetrics

    top_failures: list[TopFailure] = Field(default_factory=list)
    exception_groups: list[ExceptionGroup] = Field(default_factory=list)
    failure_clusters: list[FailureCluster] = Field(default_factory=list)

    detected_services: list[str] = Field(default_factory=list)
    detected_versions: list[str] = Field(default_factory=list)

    redaction_applied: bool = True
    analysis_notes: list[str] = Field(default_factory=list)


# -----------------------------------------------------------------------------
# API Request/Response
# -----------------------------------------------------------------------------


class AnalyzeEventsRequest(BaseModel):
    """Request to analyze log events."""

    events: list[dict[str, Any]] = Field(..., min_length=1, max_length=10000)
    baseline_events: list[dict[str, Any]] | None = Field(default=None, max_length=10000)
    redact_pii: bool = True
    include_samples: bool = True
    max_samples: int = Field(default=5, ge=1, le=20)
    top_failures_count: int = Field(default=10, ge=1, le=50)


class AnalyzeEventsResponse(BaseModel):
    """Response from event analysis."""

    summary: IntelligenceSummary
    classified_events: list[ClassifiedEvent] | None = None  # Optional, can be large


class ClassifyEventRequest(BaseModel):
    """Request to classify a single event."""

    message: str = Field(..., min_length=1, max_length=100000)
    timestamp: datetime | None = None
    log_group: str = ""
    log_stream: str | None = None
    raw_fields: dict[str, Any] = Field(default_factory=dict)
    redact_pii: bool = True


class ClassifyEventResponse(BaseModel):
    """Response from single event classification."""

    event: ClassifiedEvent
