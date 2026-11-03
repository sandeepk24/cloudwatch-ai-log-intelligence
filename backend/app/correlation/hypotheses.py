"""Root-cause hypothesis generation and evidence-based scoring.

Scoring methodology (explicit rules, not LLM output):

  Component                              Points
  ─────────────────────────────────────  ──────
  Trace / request ID link                +0.35
  Deployment version regression          +0.30
  Service dependency propagation         +0.20
  Temporal primacy (first to fail)       +0.10
  Additional corroborating signals       +0.05 each, capped at +0.15

  Contradicting evidence item            -0.20 each
  Temporal-only cap (no non-temporal)    score capped at 0.40

EvidenceStrength assignment:
  STRONG      score ≥ 0.75 AND has_non_temporal_link AND ≥3 independent signals
  MODERATE    score ≥ 0.50 AND has_non_temporal_link
  WEAK        score ≥ 0.25
  SPECULATIVE score < 0.25

The causation_caveat field is always set when temporal correlation was used,
reminding the reader that co-occurrence ≠ causation.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import timedelta
from typing import Any

from app.core.logging import get_logger
from app.schemas.incidents import (
    CorrelationMethod,
    DeploymentDelta,
    EvidenceItem,
    EvidenceKind,
    EvidenceStrength,
    RawSignal,
    RootCauseHypothesis,
    ServiceDependency,
    ServiceNode,
    SignalKind,
    SignalSeverity,
    SignalSource,
)
from .graph import can_propagate_to

logger = get_logger(__name__)

ERROR_SEVERITIES = frozenset({SignalSeverity.HIGH, SignalSeverity.CRITICAL, SignalSeverity.MEDIUM})

# Minimum error signals needed to consider a service as a hypothesis candidate
_MIN_ERROR_SIGNALS = 1

# Temporal window: two services are "co-occurring" if their first errors
# are within this window. NOT treated as causation.
_TEMPORAL_CO_OCCURRENCE_WINDOW = timedelta(minutes=10)


# ── Candidate services ────────────────────────────────────────────────────────


def _candidate_services(
    nodes: list[ServiceNode],
    signals: list[RawSignal],
) -> list[ServiceNode]:
    """Return services with at least one error signal, sorted by first error time."""
    candidates = [n for n in nodes if n.error_signal_count >= _MIN_ERROR_SIGNALS]
    # Sort by first_error_at ascending — temporally earliest errors are considered first
    candidates.sort(key=lambda n: n.first_error_at or n.signal_count)
    return candidates


# ── Evidence building blocks ──────────────────────────────────────────────────


def _build_trace_evidence(
    candidate: ServiceNode,
    all_signals: list[RawSignal],
) -> EvidenceItem | None:
    """Check if trace/request IDs link this service's errors to other services."""
    cand_error_signals = [
        s
        for s in all_signals
        if s.service_name == candidate.name and s.severity in ERROR_SEVERITIES
    ]
    # Gather all trace / request IDs from this service's errors
    trace_ids = {s.trace_id for s in cand_error_signals if s.trace_id}
    request_ids = {s.request_id for s in cand_error_signals if s.request_id}

    if not trace_ids and not request_ids:
        return None

    # Find other-service signals sharing the same IDs
    corroborating = [
        s
        for s in all_signals
        if s.service_name != candidate.name
        and s.severity in ERROR_SEVERITIES
        and (
            (s.trace_id and s.trace_id in trace_ids)
            or (s.request_id and s.request_id in request_ids)
        )
    ]
    if not corroborating:
        return None

    other_services = sorted({s.service_name for s in corroborating})
    method = (
        CorrelationMethod.TRACE_ID if trace_ids else CorrelationMethod.REQUEST_ID
    )
    strength = EvidenceStrength.STRONG if len(corroborating) >= 3 else EvidenceStrength.MODERATE
    rationale = (
        f"Same {'trace' if trace_ids else 'request'} IDs appear in errors across "
        f"{len(other_services)} other service(s): {', '.join(other_services)}. "
        "This is a direct, non-temporal link between failure events."
    )

    return EvidenceItem(
        evidence_id=str(uuid.uuid4())[:8],
        kind=EvidenceKind.SUPPORTING,
        strength=strength,
        description=(
            f"Shared {'trace' if trace_ids else 'request'} IDs link "
            f"{candidate.name} errors to {', '.join(other_services[:3])}"
        ),
        correlation_method=method,
        signal_ids=[s.signal_id for s in cand_error_signals[:5]]
        + [s.signal_id for s in corroborating[:5]],
        evidence_ptrs=[
            p
            for s in (cand_error_signals[:3] + corroborating[:3])
            if (p := s.evidence_ptr)
        ],
        strength_rationale=rationale,
    )


def _build_deployment_evidence(
    candidate: ServiceNode,
    deltas: list[DeploymentDelta],
) -> EvidenceItem | None:
    """Check if a deployment regression was detected for this service."""
    service_deltas = [d for d in deltas if d.service_name == candidate.name and d.is_regression]
    if not service_deltas:
        return None

    best = max(
        service_deltas,
        key=lambda d: (d.error_rate_change_ratio or 999, d.after_error_count),
    )
    ratio_str = (
        f"{best.error_rate_change_ratio:.1f}×"
        if best.error_rate_change_ratio is not None
        else "∞ (clean baseline)"
    )

    return EvidenceItem(
        evidence_id=str(uuid.uuid4())[:8],
        kind=EvidenceKind.SUPPORTING,
        strength=best.regression_confidence,
        description=(
            f"Deployment {best.deployment.version} correlated with "
            f"{ratio_str} error rate increase for {candidate.name} "
            f"({best.before_error_count}→{best.after_error_count} errors)"
        ),
        correlation_method=CorrelationMethod.DEPLOYMENT_VERSION,
        signal_ids=best.before_signal_ids[:5] + best.after_signal_ids[:5],
        evidence_ptrs=[],
        strength_rationale=best.regression_rationale,
    )


def _build_dependency_evidence(
    candidate: ServiceNode,
    nodes: list[ServiceNode],
    edges: list[ServiceDependency],
    all_signals: list[RawSignal],
) -> EvidenceItem | None:
    """Check if errors in this service could explain failures in services that depend on it.

    Failure propagation direction:
        candidate fails → callers of candidate also fail.

    So we look for failing nodes n where n depends on candidate
    (i.e., n can reach candidate through the dependency graph: n calls candidate).
    """
    # Find services that depend on candidate (n calls candidate transitively)
    dependent_services_with_errors = [
        n
        for n in nodes
        if n.name != candidate.name
        and n.error_signal_count > 0
        and can_propagate_to(n.name, candidate.name, edges)
    ]
    if not dependent_services_with_errors:
        return None

    affected = [n.name for n in dependent_services_with_errors]
    strength = EvidenceStrength.MODERATE if len(affected) >= 2 else EvidenceStrength.WEAK
    rationale = (
        f"{len(affected)} service(s) that depend on {candidate.name} are also showing errors "
        f"({', '.join(affected[:3])}). "
        "Failures in a shared dependency are consistent with causing caller-side errors, "
        "but dependency overlap alone does not prove causation."
    )

    return EvidenceItem(
        evidence_id=str(uuid.uuid4())[:8],
        kind=EvidenceKind.SUPPORTING,
        strength=strength,
        description=(
            f"{len(affected)} service(s) that depend on {candidate.name} show concurrent errors: "
            f"{', '.join(affected[:3])}"
        ),
        correlation_method=CorrelationMethod.SERVICE_DEPENDENCY,
        signal_ids=[],
        evidence_ptrs=[],
        strength_rationale=rationale,
    )


def _build_temporal_primacy_evidence(
    candidate: ServiceNode,
    nodes: list[ServiceNode],
) -> EvidenceItem | None:
    """Check if this service's errors started before all other services' errors."""
    other_first_errors = [
        n.first_error_at
        for n in nodes
        if n.name != candidate.name and n.first_error_at is not None
    ]
    if not other_first_errors or candidate.first_error_at is None:
        return None

    earliest_other = min(other_first_errors)
    is_first = candidate.first_error_at < earliest_other

    if not is_first:
        return None

    delta_minutes = (earliest_other - candidate.first_error_at).total_seconds() / 60
    if delta_minutes > 60:
        return None  # Too far apart to be informative

    return EvidenceItem(
        evidence_id=str(uuid.uuid4())[:8],
        kind=EvidenceKind.SUPPORTING,
        strength=EvidenceStrength.WEAK,
        description=(
            f"{candidate.name} errors began {delta_minutes:.1f} min before "
            "errors in other services"
        ),
        correlation_method=CorrelationMethod.TEMPORAL_PROXIMITY,
        signal_ids=candidate.error_signal_ids[:3],
        evidence_ptrs=[],
        strength_rationale=(
            f"{candidate.name} was the first service to show errors "
            f"({delta_minutes:.1f} min lead). "
            "Temporal precedence is consistent with being the origin but is "
            "NOT sufficient alone to establish causation."
        ),
    )


def _build_contradicting_evidence(
    candidate: ServiceNode,
    all_signals: list[RawSignal],
    deltas: list[DeploymentDelta],
) -> list[EvidenceItem]:
    """Collect evidence that argues against this hypothesis."""
    items: list[EvidenceItem] = []

    # 1. Service had errors BEFORE any other service — but if it had no errors in
    #    the baseline window, that's not contradicting.  Only contradict if the
    #    service was healthy DURING the incident window and errors appeared later.
    non_error_signals = [
        s
        for s in all_signals
        if s.service_name == candidate.name
        and s.severity not in ERROR_SEVERITIES
    ]
    error_signals = [
        s
        for s in all_signals
        if s.service_name == candidate.name and s.severity in ERROR_SEVERITIES
    ]

    # 2. Deployment delta shows no regression for this service
    service_deltas_no_regress = [
        d
        for d in deltas
        if d.service_name == candidate.name and not d.is_regression
    ]
    if service_deltas_no_regress:
        delta = service_deltas_no_regress[0]
        items.append(
            EvidenceItem(
                evidence_id=str(uuid.uuid4())[:8],
                kind=EvidenceKind.CONTRADICTING,
                strength=EvidenceStrength.WEAK,
                description=(
                    f"No meaningful error rate increase after deployment "
                    f"of {delta.deployment.version} on {candidate.name}"
                ),
                correlation_method=CorrelationMethod.DEPLOYMENT_VERSION,
                signal_ids=[],
                evidence_ptrs=[],
                strength_rationale=delta.regression_rationale,
            )
        )

    # 3. Large volume of healthy signals during the incident
    if non_error_signals and error_signals:
        health_ratio = len(non_error_signals) / (len(error_signals) + len(non_error_signals))
        if health_ratio > 0.9:
            items.append(
                EvidenceItem(
                    evidence_id=str(uuid.uuid4())[:8],
                    kind=EvidenceKind.CONTRADICTING,
                    strength=EvidenceStrength.WEAK,
                    description=(
                        f"{candidate.name} had {len(non_error_signals)} healthy signals "
                        f"alongside {len(error_signals)} errors ({health_ratio:.0%} healthy)"
                    ),
                    correlation_method=CorrelationMethod.TEMPORAL_PROXIMITY,
                    signal_ids=[s.signal_id for s in non_error_signals[:3]],
                    evidence_ptrs=[],
                    strength_rationale=(
                        f"{health_ratio:.0%} of signals from this service were non-error. "
                        "High healthy ratio reduces confidence that this service was fully impaired."
                    ),
                )
            )

    return items


# ── Scoring ───────────────────────────────────────────────────────────────────


def _score_hypothesis(
    supporting: list[EvidenceItem],
    contradicting: list[EvidenceItem],
) -> tuple[float, dict[str, float]]:
    """Compute hypothesis score from evidence items using explicit rules."""
    breakdown: dict[str, float] = {}
    score = 0.0
    has_non_temporal = False

    for item in supporting:
        if item.correlation_method == CorrelationMethod.TRACE_ID:
            pts = 0.35
            breakdown["trace_id_link"] = pts
            has_non_temporal = True
        elif item.correlation_method == CorrelationMethod.REQUEST_ID:
            pts = 0.35
            breakdown["request_id_link"] = pts
            has_non_temporal = True
        elif item.correlation_method == CorrelationMethod.DEPLOYMENT_VERSION:
            pts = 0.30
            breakdown["deployment_regression"] = pts
            has_non_temporal = True
        elif item.correlation_method == CorrelationMethod.SERVICE_DEPENDENCY:
            pts = 0.20
            breakdown["service_dependency"] = pts
            has_non_temporal = True
        elif item.correlation_method == CorrelationMethod.TEMPORAL_PROXIMITY:
            pts = 0.10
            breakdown["temporal_primacy"] = pts
        elif item.correlation_method == CorrelationMethod.ALARM_DIMENSION:
            pts = 0.15
            breakdown["alarm_dimension"] = pts
            has_non_temporal = True
        elif item.correlation_method == CorrelationMethod.METRIC_COMOVEMENT:
            pts = 0.15
            breakdown["metric_comovement"] = pts
            has_non_temporal = True
        else:
            pts = 0.05
            breakdown[f"other_{item.correlation_method}"] = pts
        score += pts

    # Additional signals bonus (each extra independent signal beyond first: +0.05, capped at 0.15)
    extra = max(0, len(supporting) - 1)
    bonus = min(0.15, extra * 0.05)
    if bonus > 0:
        breakdown["multi_signal_corroboration"] = bonus
        score += bonus

    # Contradicting deductions
    for item in contradicting:
        penalty = 0.20
        breakdown[f"contradiction_{item.evidence_id}"] = -penalty
        score -= penalty

    # Temporal-only cap
    if not has_non_temporal:
        score = min(score, 0.40)
        breakdown["temporal_only_cap_applied"] = 0.0

    return round(max(0.0, min(1.0, score)), 3), breakdown


def _strength_from_score(
    score: float,
    has_non_temporal: bool,
    corroborating_count: int,
) -> EvidenceStrength:
    """Map numeric score to evidence strength category per explicit criteria."""
    if score >= 0.75 and has_non_temporal and corroborating_count >= 3:
        return EvidenceStrength.STRONG
    if score >= 0.50 and has_non_temporal:
        return EvidenceStrength.MODERATE
    if score >= 0.25:
        return EvidenceStrength.WEAK
    return EvidenceStrength.SPECULATIVE


# ── Investigation steps ───────────────────────────────────────────────────────

_STEPS_BY_SOURCE: dict[SignalSource, list[str]] = {
    SignalSource.RDS: [
        "Check RDS Performance Insights for active slow queries and lock waits.",
        "Review CloudWatch metric `DatabaseConnections` — compare to max_connections parameter.",
        "Examine RDS error logs in CloudWatch for OOM, deadlock, or crash events.",
        "Check whether read-replica replication lag spiked during the window.",
        "Verify RDS instance class has sufficient CPU/RAM for current load.",
    ],
    SignalSource.ECS: [
        "Review stopped ECS task reasons in the ECS console (Tasks → Stopped).",
        "Check CloudWatch Container Insights for memory/CPU at task failure time.",
        "Examine ECS service event log for deployment failure messages.",
        "Review ECS task definition for resource limits (CPU/memory) that may cause OOM.",
        "Check Service Connect or service discovery logs for connection issues.",
    ],
    SignalSource.EKS: [
        "Run `kubectl describe pod <pod> -n <namespace>` for exit reason and OOMKilled flag.",
        "Check Kubernetes events: `kubectl get events --sort-by=.lastTimestamp`.",
        "Review node-level metrics (CPU, memory, disk) via CloudWatch Container Insights.",
        "Examine application logs in CloudWatch from the failing pod's log stream.",
        "Verify resource requests/limits are set appropriately in the pod spec.",
    ],
    SignalSource.LAMBDA: [
        "Check Lambda function logs for stack traces and error messages.",
        "Review CloudWatch metric `Throttles` — compare to reserved concurrency setting.",
        "Examine `Init Duration` in logs to detect cold-start saturation.",
        "Verify downstream dependencies (RDS, DynamoDB, S3) are reachable from the VPC.",
        "Review Lambda timeout setting vs. observed execution durations.",
    ],
    SignalSource.ALB: [
        "Examine ALB access logs for 5xx target group members and error distribution.",
        "Review target group health check settings and threshold timing.",
        "Check CloudWatch metric `TargetConnectionErrorCount` for connection issues.",
        "Correlate ALB latency spike with ECS/EKS deployment timestamps.",
        "Review WAF logs if ALB has WAF attached for unexpected rule blocks.",
    ],
    SignalSource.EC2: [
        "Check EC2 system logs via EC2 console → Actions → Get System Log.",
        "Review CloudWatch metric `mem_used_percent` and `disk_used_percent`.",
        "Check for OS-level OOM events in `/var/log/syslog` or `/var/log/messages`.",
        "Verify instance type is appropriate for workload memory requirements.",
        "Check Auto Scaling Group activities for unexpected termination events.",
    ],
    SignalSource.CLOUDWATCH_ALARM: [
        "Review the alarm's metric and dimensions to identify the exact resource.",
        "Check alarm history in CloudWatch for repeated state transitions.",
        "Trace the alarm metric to its source resource for detailed diagnostics.",
        "Verify alarm thresholds are appropriate and not triggered by normal load patterns.",
    ],
}

_GENERIC_STEPS = [
    "Correlate timestamps across all affected services to establish the precise sequence.",
    "Check for any recent IAM policy changes that could affect service permissions.",
    "Review VPC network ACLs and security groups for any changes around the incident.",
    "Search distributed tracing (X-Ray) for traces spanning the incident window.",
]


def build_investigation_steps(
    source: SignalSource,
    is_deployment_related: bool,
) -> list[str]:
    """Build an ordered list of concrete investigation steps."""
    steps = list(_STEPS_BY_SOURCE.get(source, _GENERIC_STEPS))
    if is_deployment_related:
        steps.insert(
            0,
            "Compare the Git diff between the deployed version and the prior version "
            "for changes to connection handling, memory allocation, or timeouts.",
        )
        steps.insert(
            1,
            "Run a rollback of the deployment and monitor for error rate recovery "
            "(if rollback is safe given current state).",
        )
    return steps


# ── Main hypothesis generator ─────────────────────────────────────────────────


def generate_hypotheses(
    all_signals: list[RawSignal],
    nodes: list[ServiceNode],
    edges: list[ServiceDependency],
    deltas: list[DeploymentDelta],
    max_hypotheses: int = 5,
) -> list[RootCauseHypothesis]:
    """Generate and rank root-cause hypotheses for all candidate services."""
    candidates = _candidate_services(nodes, all_signals)
    hypotheses: list[RootCauseHypothesis] = []

    for candidate in candidates:
        supporting: list[EvidenceItem] = []
        contradicting: list[EvidenceItem] = []

        # Build all evidence items
        if (ev := _build_trace_evidence(candidate, all_signals)):
            supporting.append(ev)
        if (ev := _build_deployment_evidence(candidate, deltas)):
            supporting.append(ev)
        if (ev := _build_dependency_evidence(candidate, nodes, edges, all_signals)):
            supporting.append(ev)
        if (ev := _build_temporal_primacy_evidence(candidate, nodes)):
            supporting.append(ev)
        contradicting.extend(_build_contradicting_evidence(candidate, all_signals, deltas))

        score, breakdown = _score_hypothesis(supporting, contradicting)
        has_non_temporal = any(
            e.correlation_method
            not in {CorrelationMethod.TEMPORAL_PROXIMITY, CorrelationMethod.SHARED_LOG_GROUP}
            for e in supporting
        )
        strength = _strength_from_score(score, has_non_temporal, len(supporting))

        # Causation caveat (always include if temporal was used)
        caveat = None
        if any(
            e.correlation_method == CorrelationMethod.TEMPORAL_PROXIMITY for e in supporting
        ):
            caveat = (
                "Temporal co-occurrence was used as supporting evidence. "
                "Shared timing does not establish causation: the service may be a "
                "victim of the actual root cause rather than the origin."
            )

        is_deployment_related = any(
            e.correlation_method == CorrelationMethod.DEPLOYMENT_VERSION for e in supporting
        )

        # Error signal kinds for this service
        error_kinds = list(
            {
                s.kind
                for s in all_signals
                if s.service_name == candidate.name and s.severity in ERROR_SEVERITIES
            }
        )

        title = _build_title(candidate, supporting, deltas)
        description = _build_description(candidate, supporting, strength)

        hypotheses.append(
            RootCauseHypothesis(
                hypothesis_id=str(uuid.uuid4())[:8],
                rank=0,  # filled after sorting
                title=title,
                description=description,
                implicated_service=candidate.name,
                implicated_signal_kinds=error_kinds,
                supporting_evidence=supporting,
                contradicting_evidence=contradicting,
                evidence_strength=strength,
                score=score,
                score_breakdown=breakdown,
                causation_caveat=caveat,
                investigation_steps=build_investigation_steps(
                    candidate.source, is_deployment_related
                ),
            )
        )

    # Sort by score descending, assign ranks
    hypotheses.sort(key=lambda h: h.score, reverse=True)
    for i, h in enumerate(hypotheses[:max_hypotheses]):
        h.rank = i + 1

    return hypotheses[:max_hypotheses]


def _build_title(
    candidate: ServiceNode,
    supporting: list[EvidenceItem],
    deltas: list[DeploymentDelta],
) -> str:
    methods = {e.correlation_method for e in supporting}
    if CorrelationMethod.DEPLOYMENT_VERSION in methods:
        service_deltas = [d for d in deltas if d.service_name == candidate.name and d.is_regression]
        version = service_deltas[0].deployment.version if service_deltas else "new version"
        return f"Deployment regression in {candidate.name} ({version})"
    if CorrelationMethod.TRACE_ID in methods or CorrelationMethod.REQUEST_ID in methods:
        return f"Traced failure origin in {candidate.name}"
    if CorrelationMethod.SERVICE_DEPENDENCY in methods:
        return f"{candidate.name} dependency failure propagating to callers"
    source_labels = {
        SignalSource.RDS: "Database saturation",
        SignalSource.LAMBDA: "Lambda execution failure",
        SignalSource.ALB: "Load balancer routing failure",
        SignalSource.EC2: "Host-level resource exhaustion",
        SignalSource.ECS: "ECS task failure",
        SignalSource.EKS: "EKS pod failure",
    }
    prefix = source_labels.get(candidate.source, "Service failure")
    return f"{prefix} in {candidate.name}"


def _build_description(
    candidate: ServiceNode,
    supporting: list[EvidenceItem],
    strength: EvidenceStrength,
) -> str:
    parts = [
        f"{candidate.name} recorded {candidate.error_signal_count} error signal(s) "
        f"during the incident window."
    ]
    for ev in supporting[:2]:
        parts.append(ev.description + ".")
    strength_phrases = {
        EvidenceStrength.STRONG: "Multiple independent lines of evidence strongly implicate this service.",
        EvidenceStrength.MODERATE: "Evidence moderately implicates this service as the origin.",
        EvidenceStrength.WEAK: "Evidence is limited; this service warrants investigation but may be a victim.",
        EvidenceStrength.SPECULATIVE: "Insufficient evidence; this is a speculative candidate only.",
    }
    parts.append(strength_phrases[strength])
    return " ".join(parts)
