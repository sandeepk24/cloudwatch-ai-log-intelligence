"""Schemas for the cross-service Incident Correlation Engine.

Design principles:
- Evidence provenance: every finding references specific signal IDs and log pointers.
- Calibrated confidence: strength is assigned by explicit, auditable criteria —
  never arbitrary LLM-generated percentages.
- Causation guard: temporal proximity alone never asserts causation.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


# ── Signal taxonomy ───────────────────────────────────────────────────────────


class SignalSource(StrEnum):
    ECS = "ecs"
    EKS = "eks"
    EC2 = "ec2"
    LAMBDA = "lambda"
    ALB = "alb"
    RDS = "rds"
    CLOUDWATCH_ALARM = "cloudwatch_alarm"
    UNKNOWN = "unknown"


class SignalKind(StrEnum):
    # ECS
    ECS_TASK_FAILURE = "ecs_task_failure"
    ECS_DEPLOYMENT_EVENT = "ecs_deployment_event"
    ECS_SERVICE_DEGRADED = "ecs_service_degraded"
    # EKS
    EKS_POD_RESTART = "eks_pod_restart"
    EKS_APP_LOG_ERROR = "eks_app_log_error"
    EKS_OOM_KILLED = "eks_oom_killed"
    # EC2
    EC2_METRIC_ANOMALY = "ec2_metric_anomaly"
    EC2_STATUS_CHECK_FAILURE = "ec2_status_check_failure"
    # Lambda
    LAMBDA_INVOCATION_FAILURE = "lambda_invocation_failure"
    LAMBDA_TIMEOUT = "lambda_timeout"
    LAMBDA_ERROR_RATE = "lambda_error_rate"
    LAMBDA_THROTTLE = "lambda_throttle"
    # ALB
    ALB_TARGET_5XX = "alb_target_5xx"
    ALB_HIGH_LATENCY = "alb_high_latency"
    ALB_UNHEALTHY_HOSTS = "alb_unhealthy_hosts"
    # RDS
    RDS_CONNECTION_ERROR = "rds_connection_error"
    RDS_HIGH_CPU = "rds_high_cpu"
    RDS_AVAILABILITY_EVENT = "rds_availability_event"
    RDS_MAX_CONNECTIONS = "rds_max_connections"
    RDS_REPLICATION_LAG = "rds_replication_lag"
    # CloudWatch Alarms
    ALARM_TRIGGERED = "alarm_triggered"
    ALARM_RESOLVED = "alarm_resolved"
    # Generic
    LOG_ERROR = "log_error"
    METRIC_SPIKE = "metric_spike"


class SignalSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ── Evidence confidence taxonomy ─────────────────────────────────────────────
#
# Strength is assigned by EXPLICIT, AUDITABLE CRITERIA — not by model output.
# See hypotheses.py for the exact scoring rules that map to each level.


class EvidenceStrength(StrEnum):
    """Explicit rule-based evidence strength.

    STRONG    — ≥3 independent corroborating signals AND at least one
                non-temporal link (trace/request ID or deployment regression).
    MODERATE  — ≥2 corroborating signals AND at least one non-temporal link.
    WEAK      — Temporal proximity only (within configurable window), or
                single non-temporal signal.
    SPECULATIVE — Circumstantial / single temporal signal / insufficient data.
    """

    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"
    SPECULATIVE = "speculative"


class EvidenceKind(StrEnum):
    SUPPORTING = "supporting"
    CONTRADICTING = "contradicting"
    NEUTRAL = "neutral"


# ── Correlation link types ────────────────────────────────────────────────────


class CorrelationMethod(StrEnum):
    TRACE_ID = "trace_id"
    REQUEST_ID = "request_id"
    DEPLOYMENT_VERSION = "deployment_version"
    SERVICE_DEPENDENCY = "service_dependency"
    TEMPORAL_PROXIMITY = "temporal_proximity"
    SHARED_LOG_GROUP = "shared_log_group"
    ALARM_DIMENSION = "alarm_dimension"
    METRIC_COMOVEMENT = "metric_comovement"


# ── Core signal model ─────────────────────────────────────────────────────────


class RawSignal(BaseModel):
    """A normalized event from any AWS service.

    Fields annotated with "Correlation key" enable cross-signal joining.
    Any two signals sharing a non-None value on the same key are considered
    directly linked (stronger than temporal proximity alone).
    """

    signal_id: str
    source: SignalSource
    kind: SignalKind
    severity: SignalSeverity
    timestamp: datetime

    # Identity
    service_name: str
    resource_id: str | None = None  # ARN, instance ID, task ARN, etc.
    log_group: str | None = None
    log_stream: str | None = None
    region: str = "us-east-1"
    account_id: str | None = None

    # Correlation keys — non-None enables cross-signal join
    trace_id: str | None = None  # X-Ray / OTEL trace ID
    request_id: str | None = None  # AWS request ID or app-level correlation ID
    deployment_version: str | None = None  # Image tag / Git SHA / task def revision

    # Content
    message: str
    metric_name: str | None = None
    metric_value: float | None = None
    metric_unit: str | None = None

    # Evidence pointer — links back to original raw log entry / CloudWatch record
    evidence_ptr: str | None = None
    raw_data: dict[str, Any] = Field(default_factory=dict)


# ── Timeline ──────────────────────────────────────────────────────────────────


class TimelineEvent(BaseModel):
    """A single entry on the incident timeline."""

    event_id: str
    timestamp: datetime
    source: SignalSource
    kind: SignalKind
    severity: SignalSeverity
    service_name: str
    description: str
    is_deployment: bool = False
    correlation_methods: list[CorrelationMethod] = Field(default_factory=list)
    evidence_ptr: str | None = None
    signal_ids: list[str] = Field(default_factory=list)


# ── Service dependency graph ──────────────────────────────────────────────────


class ServiceDependency(BaseModel):
    upstream: str  # caller / client
    downstream: str  # callee / dependency
    dependency_type: str = "synchronous"  # synchronous | async | database | cache


class ServiceNode(BaseModel):
    """A service observed during the incident window."""

    name: str
    source: SignalSource
    signal_count: int = 0
    error_signal_count: int = 0
    first_error_at: datetime | None = None
    last_error_at: datetime | None = None
    deployment_version: str | None = None
    deployment_at: datetime | None = None
    # Ordered list of error signal IDs — proves the timeline of this service's errors
    error_signal_ids: list[str] = Field(default_factory=list)


# ── Deployment analysis ───────────────────────────────────────────────────────


class DeploymentEvent(BaseModel):
    service_name: str
    version: str
    deployed_at: datetime
    deployer: str | None = None
    signal_id: str


class DeploymentDelta(BaseModel):
    """Before-vs-after error rate comparison across a single deployment boundary.

    Criteria for regression_confidence:
      STRONG   — error_rate_change_ratio ≥ 5 AND after_error_count ≥ 5
      MODERATE — error_rate_change_ratio ≥ 2 AND after_error_count ≥ 2
      WEAK     — error_rate_change_ratio > 1 AND after_error_count ≥ 1
      SPECULATIVE — insufficient data in before or after window
    """

    deployment: DeploymentEvent
    service_name: str

    before_window_minutes: int
    before_error_count: int
    before_error_rate_per_minute: float
    before_signal_ids: list[str] = Field(default_factory=list)

    after_window_minutes: int
    after_error_count: int
    after_error_rate_per_minute: float
    after_signal_ids: list[str] = Field(default_factory=list)

    # ratio = after_rate / before_rate; None if before_rate == 0 (clean baseline)
    error_rate_change_ratio: float | None
    error_increase_absolute: int
    is_regression: bool
    regression_confidence: EvidenceStrength
    # Human-readable rationale for why this is/isn't classified as regression
    regression_rationale: str


# ── Evidence ──────────────────────────────────────────────────────────────────


class EvidenceItem(BaseModel):
    """A single piece of evidence for or against a hypothesis.

    Every item carries:
    - The correlation method that surfaced it (explicit, not inferred from LLM)
    - The signal IDs and evidence pointers that back it
    - The exact strength criteria that were met
    """

    evidence_id: str
    kind: EvidenceKind
    strength: EvidenceStrength
    description: str
    correlation_method: CorrelationMethod
    signal_ids: list[str] = Field(default_factory=list)
    evidence_ptrs: list[str] = Field(default_factory=list)
    # Verbatim statement of which criteria from EvidenceStrength docstring were met
    strength_rationale: str


# ── Root cause hypotheses ─────────────────────────────────────────────────────


class RootCauseHypothesis(BaseModel):
    """A ranked, evidence-backed root-cause hypothesis.

    Score is computed by an explicit rule engine (see hypotheses.py).
    It is NOT produced by an LLM and is NOT an arbitrary percentage.
    The score_breakdown field shows every additive/subtractive component.
    """

    hypothesis_id: str
    rank: int
    title: str
    description: str

    implicated_service: str
    implicated_signal_kinds: list[SignalKind] = Field(default_factory=list)

    supporting_evidence: list[EvidenceItem] = Field(default_factory=list)
    contradicting_evidence: list[EvidenceItem] = Field(default_factory=list)

    evidence_strength: EvidenceStrength

    # Score 0–1, built from explicit rules (see score_breakdown for details)
    score: float = Field(ge=0.0, le=1.0)
    score_breakdown: dict[str, float] = Field(default_factory=dict)

    # Explicit causation guard — always present when temporal correlation was used
    causation_caveat: str | None = None

    investigation_steps: list[str] = Field(default_factory=list)


# ── Infrastructure symptoms ───────────────────────────────────────────────────


class InfrastructureSymptom(BaseModel):
    """A correlated infrastructure-level symptom cluster."""

    symptom_id: str
    category: str  # e.g. "memory_pressure", "db_saturation", "network_latency"
    affected_resources: list[str]
    signal_ids: list[str] = Field(default_factory=list)
    first_observed: datetime
    last_observed: datetime
    description: str
    peak_metric_value: float | None = None
    peak_metric_unit: str | None = None


# ── Error onset analysis ──────────────────────────────────────────────────────


class ErrorOnset(BaseModel):
    """When and how fast errors began during the incident window."""

    first_error_at: datetime
    first_error_signal_id: str
    onset_rate_per_minute: float  # errors/min in first 5-min onset window
    peak_rate_per_minute: float
    peak_at: datetime
    error_kinds: list[str]
    affected_services: list[str]
    # Time from first error to peak (minutes) — large value = slow onset
    time_to_peak_minutes: float


# ── Full incident report ──────────────────────────────────────────────────────


class IncidentReport(BaseModel):
    """Complete cross-service incident correlation report.

    All findings carry explicit evidence provenance.
    Confidence is calibrated by rule-based criteria, not LLM output.
    """

    report_id: str
    generated_at: datetime
    incident_window_start: datetime
    incident_window_end: datetime

    total_signals_ingested: int
    signals_by_source: dict[str, int] = Field(default_factory=dict)
    signals_by_kind: dict[str, int] = Field(default_factory=dict)

    # Chronological timeline
    timeline: list[TimelineEvent] = Field(default_factory=list)

    # Affected services and their dependency relationships
    affected_services: list[ServiceNode] = Field(default_factory=list)
    service_dependencies: list[ServiceDependency] = Field(default_factory=list)

    # When errors first appeared and how they ramped
    error_onset: ErrorOnset | None = None

    # Infrastructure-layer symptoms
    infrastructure_symptoms: list[InfrastructureSymptom] = Field(default_factory=list)

    # Deployment context
    deployment_events: list[DeploymentEvent] = Field(default_factory=list)
    deployment_deltas: list[DeploymentDelta] = Field(default_factory=list)

    # Ranked root causes — highest-scoring first
    root_cause_hypotheses: list[RootCauseHypothesis] = Field(default_factory=list)

    # Plain-language summary (rule-assembled, not LLM-generated)
    executive_summary: str
    analysis_notes: list[str] = Field(default_factory=list)


# ── API Request / Response ────────────────────────────────────────────────────


class AnalyzeIncidentRequest(BaseModel):
    """Run the incident correlation engine over provided signals."""

    signals: list[dict[str, Any]] = Field(..., min_length=1, max_length=50_000)
    incident_window_minutes: int = Field(default=60, ge=5, le=1440)
    # How far back before a deployment to look for the baseline error rate
    deployment_lookback_minutes: int = Field(default=30, ge=5, le=720)
    # How far after a deployment to measure the post-deploy error rate
    deployment_after_minutes: int = Field(default=30, ge=5, le=720)
    # Explicit service dependency edges to seed the graph
    known_dependencies: list[dict[str, str]] = Field(default_factory=list)
    include_timeline: bool = True
    max_hypotheses: int = Field(default=5, ge=1, le=10)


class AnalyzeIncidentResponse(BaseModel):
    report: IncidentReport


class SyntheticScenarioRequest(BaseModel):
    """Generate a synthetic multi-service failure scenario for testing."""

    scenario_name: str = "db_cascade_failure"
    seed: int | None = None


class SyntheticScenarioResponse(BaseModel):
    scenario_name: str
    description: str
    signals: list[dict[str, Any]]
    expected_root_cause: str
    expected_deployment_regression: bool
    signal_count: int
