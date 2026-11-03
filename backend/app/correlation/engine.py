"""CorrelationEngine — main orchestrator for cross-service incident analysis.

Usage:
    engine = CorrelationEngine()
    report = engine.analyze(signals_raw, request)
"""

from __future__ import annotations

import uuid
from collections import Counter, defaultdict
from datetime import UTC, datetime
from typing import Any

from app.core.logging import get_logger
from app.schemas.incidents import (
    AnalyzeIncidentRequest,
    IncidentReport,
    InfrastructureSymptom,
    RawSignal,
    SignalKind,
    SignalSeverity,
    SignalSource,
)
from .deployment import compute_deployment_deltas, extract_deployment_events
from .graph import build_service_graph
from .hypotheses import generate_hypotheses
from .signals import normalize_signals
from .timeline import build_timeline, compute_error_onset

logger = get_logger(__name__)

ERROR_SEVERITIES = frozenset({SignalSeverity.HIGH, SignalSeverity.CRITICAL, SignalSeverity.MEDIUM})


class CorrelationEngine:
    """Orchestrates the full incident correlation pipeline."""

    def analyze(
        self,
        raw_signals: list[dict[str, Any]],
        request: AnalyzeIncidentRequest,
    ) -> IncidentReport:
        """Run the complete correlation pipeline.

        Steps:
        1.  Normalize raw signal dicts → typed RawSignal objects
        2.  Build service graph (nodes + dependency edges)
        3.  Build chronological timeline
        4.  Compute error onset metrics
        5.  Extract and analyze deployment boundaries
        6.  Detect infrastructure symptom clusters
        7.  Generate and rank root-cause hypotheses
        8.  Assemble the IncidentReport
        """
        report_id = str(uuid.uuid4())[:8]
        now = datetime.now(UTC)

        logger.info(
            "CorrelationEngine.analyze report_id=%s raw_signal_count=%d",
            report_id,
            len(raw_signals),
        )

        # 1. Normalize
        signals = normalize_signals(raw_signals)
        if not signals:
            return self._empty_report(report_id, now)

        # Sort by timestamp for all subsequent operations
        signals.sort(key=lambda s: s.timestamp)

        # Determine incident window
        window_start = signals[0].timestamp
        window_end = signals[-1].timestamp

        # 2. Service graph
        nodes, edges = build_service_graph(signals, request.known_dependencies)

        # Seed the graph with any explicit dependency edges
        if request.known_dependencies:
            from .graph import _build_edges  # noqa: PLC0415
            extra_edges = _build_edges(
                {n.name: n.source for n in nodes},
                request.known_dependencies,
            )
            # Merge (no duplicates)
            existing = {(e.upstream, e.downstream) for e in edges}
            for edge in extra_edges:
                if (edge.upstream, edge.downstream) not in existing:
                    edges.append(edge)
                    existing.add((edge.upstream, edge.downstream))

        # 3. Timeline
        timeline = build_timeline(signals) if request.include_timeline else []

        # 4. Error onset
        error_onset = compute_error_onset(signals)

        # 5. Deployment analysis
        deployment_events = extract_deployment_events(signals)
        deployment_deltas = compute_deployment_deltas(
            signals=signals,
            deployments=deployment_events,
            before_window_minutes=request.deployment_lookback_minutes,
            after_window_minutes=request.deployment_after_minutes,
        )

        # 6. Infrastructure symptoms
        symptoms = self._detect_infrastructure_symptoms(signals)

        # 7. Hypotheses
        hypotheses = generate_hypotheses(
            all_signals=signals,
            nodes=nodes,
            edges=edges,
            deltas=deployment_deltas,
            max_hypotheses=request.max_hypotheses,
        )

        # 8. Assemble report
        signals_by_source = dict(Counter(s.source for s in signals))
        signals_by_kind = dict(Counter(str(s.kind) for s in signals))

        summary = self._build_executive_summary(
            signals=signals,
            nodes=nodes,
            hypotheses=hypotheses,
            deployment_deltas=deployment_deltas,
            error_onset=error_onset,
        )

        notes = self._build_analysis_notes(signals, nodes, deployment_events, hypotheses)

        return IncidentReport(
            report_id=report_id,
            generated_at=now,
            incident_window_start=window_start,
            incident_window_end=window_end,
            total_signals_ingested=len(signals),
            signals_by_source=signals_by_source,
            signals_by_kind=signals_by_kind,
            timeline=timeline,
            affected_services=nodes,
            service_dependencies=edges,
            error_onset=error_onset,
            infrastructure_symptoms=symptoms,
            deployment_events=deployment_events,
            deployment_deltas=deployment_deltas,
            root_cause_hypotheses=hypotheses,
            executive_summary=summary,
            analysis_notes=notes,
        )

    # ── Infrastructure symptoms ───────────────────────────────────────────────

    def _detect_infrastructure_symptoms(
        self,
        signals: list[RawSignal],
    ) -> list[InfrastructureSymptom]:
        """Cluster related infrastructure signals into named symptom groups."""
        symptoms: list[InfrastructureSymptom] = []

        # Group by symptom category
        categories: dict[str, list[RawSignal]] = defaultdict(list)
        for sig in signals:
            category = _signal_symptom_category(sig)
            if category:
                categories[category].append(sig)

        for category, cat_signals in categories.items():
            if not cat_signals:
                continue
            timestamps = [s.timestamp for s in cat_signals]
            affected_resources = sorted(
                {s.resource_id or s.service_name for s in cat_signals}
            )
            peak_value = None
            peak_unit = None
            metric_signals = [s for s in cat_signals if s.metric_value is not None]
            if metric_signals:
                peak_sig = max(metric_signals, key=lambda s: s.metric_value or 0)
                peak_value = peak_sig.metric_value
                peak_unit = peak_sig.metric_unit

            symptoms.append(
                InfrastructureSymptom(
                    symptom_id=str(uuid.uuid4())[:8],
                    category=category,
                    affected_resources=affected_resources,
                    signal_ids=[s.signal_id for s in cat_signals],
                    first_observed=min(timestamps),
                    last_observed=max(timestamps),
                    description=_symptom_description(category, cat_signals),
                    peak_metric_value=peak_value,
                    peak_metric_unit=peak_unit,
                )
            )

        symptoms.sort(key=lambda s: s.first_observed)
        return symptoms

    # ── Narrative generation ──────────────────────────────────────────────────

    def _build_executive_summary(
        self,
        signals: list[RawSignal],
        nodes,
        hypotheses,
        deployment_deltas,
        error_onset,
    ) -> str:
        """Build a rule-assembled (non-LLM) executive summary."""
        error_signals = [s for s in signals if s.severity in ERROR_SEVERITIES]
        affected_count = len({n.name for n in nodes if n.error_signal_count > 0})
        total_services = len(nodes)

        parts = [
            f"Incident analysis over {len(signals)} signals across "
            f"{total_services} service(s). "
            f"{len(error_signals)} error-severity signal(s) detected "
            f"across {affected_count} service(s)."
        ]

        if error_onset:
            parts.append(
                f"Errors first appeared at {error_onset.first_error_at.strftime('%H:%M:%S UTC')} "
                f"with an onset rate of {error_onset.onset_rate_per_minute:.1f} errors/min, "
                f"peaking at {error_onset.peak_rate_per_minute:.1f} errors/min."
            )

        regressions = [d for d in deployment_deltas if d.is_regression]
        if regressions:
            reg = regressions[0]
            parts.append(
                f"A deployment regression was detected: {reg.deployment.service_name} "
                f"version {reg.deployment.version} correlated with a "
                f"{'∞×' if reg.error_rate_change_ratio is None else f'{reg.error_rate_change_ratio:.1f}×'}"
                f" error rate increase ({reg.regression_confidence} confidence)."
            )

        if hypotheses:
            top = hypotheses[0]
            parts.append(
                f"Top root-cause hypothesis ({top.evidence_strength} evidence): "
                f"{top.title}."
            )
        else:
            parts.append("No root-cause hypotheses could be formed from available signals.")

        return " ".join(parts)

    def _build_analysis_notes(
        self,
        signals: list[RawSignal],
        nodes,
        deployment_events,
        hypotheses,
    ) -> list[str]:
        """Build a list of analyst-facing notes about data quality and gaps."""
        notes: list[str] = []

        # Check for missing correlation IDs
        error_signals = [s for s in signals if s.severity in ERROR_SEVERITIES]
        missing_trace = sum(1 for s in error_signals if not s.trace_id and not s.request_id)
        if missing_trace > 0:
            pct = missing_trace / max(1, len(error_signals)) * 100
            notes.append(
                f"{missing_trace} error signal(s) ({pct:.0f}%) lack trace/request IDs — "
                "enabling distributed tracing (X-Ray, OTEL) would enable stronger correlation."
            )

        # Check for temporal-only hypotheses
        temporal_only = [
            h for h in hypotheses
            if all(
                "temporal" in str(e.correlation_method).lower()
                for e in h.supporting_evidence
            )
        ]
        if temporal_only:
            notes.append(
                f"{len(temporal_only)} hypothesis/es rely solely on temporal correlation. "
                "These cannot confirm causation without additional linking evidence."
            )

        # Alert if no deployments found
        if not deployment_events:
            notes.append(
                "No deployment events detected in the signal set. "
                "If a deployment occurred, ensure ECS deployment events or "
                "CodeDeploy notifications are included in the signals."
            )

        # Check for alarm signals
        alarm_signals = [s for s in signals if s.source == SignalSource.CLOUDWATCH_ALARM]
        if not alarm_signals:
            notes.append(
                "No CloudWatch Alarm signals found. "
                "Including alarm state-change events improves root-cause confidence."
            )

        # Short window warning
        if signals:
            window_minutes = (
                signals[-1].timestamp - signals[0].timestamp
            ).total_seconds() / 60
            if window_minutes < 10:
                notes.append(
                    f"Incident window is only {window_minutes:.1f} minutes. "
                    "A wider window improves baseline comparison and deployment analysis."
                )

        return notes

    # ── Empty report ──────────────────────────────────────────────────────────

    @staticmethod
    def _empty_report(report_id: str, now: datetime) -> IncidentReport:
        return IncidentReport(
            report_id=report_id,
            generated_at=now,
            incident_window_start=now,
            incident_window_end=now,
            total_signals_ingested=0,
            executive_summary="No signals could be parsed from the provided input.",
            analysis_notes=["All provided signals were malformed or unparseable."],
        )


# ── Module-level convenience function ────────────────────────────────────────


_engine: CorrelationEngine | None = None


def correlate_incident(
    raw_signals: list[dict[str, Any]],
    request: AnalyzeIncidentRequest,
) -> IncidentReport:
    """Convenience function using a shared CorrelationEngine instance."""
    global _engine
    if _engine is None:
        _engine = CorrelationEngine()
    return _engine.analyze(raw_signals, request)


# ── Helpers ───────────────────────────────────────────────────────────────────


_SYMPTOM_CATEGORIES: list[tuple[set[SignalKind], str]] = [
    ({SignalKind.RDS_HIGH_CPU, SignalKind.RDS_MAX_CONNECTIONS}, "db_saturation"),
    ({SignalKind.RDS_CONNECTION_ERROR, SignalKind.RDS_AVAILABILITY_EVENT}, "db_connectivity"),
    ({SignalKind.ECS_TASK_FAILURE, SignalKind.ECS_SERVICE_DEGRADED}, "ecs_task_failures"),
    ({SignalKind.EKS_OOM_KILLED, SignalKind.EKS_POD_RESTART}, "pod_oom_restarts"),
    ({SignalKind.EC2_METRIC_ANOMALY, SignalKind.EC2_STATUS_CHECK_FAILURE}, "host_resource_pressure"),
    ({SignalKind.LAMBDA_TIMEOUT, SignalKind.LAMBDA_THROTTLE, SignalKind.LAMBDA_ERROR_RATE}, "lambda_execution_failures"),
    ({SignalKind.ALB_TARGET_5XX, SignalKind.ALB_UNHEALTHY_HOSTS}, "load_balancer_errors"),
    ({SignalKind.ALB_HIGH_LATENCY}, "elevated_latency"),
    ({SignalKind.ALARM_TRIGGERED}, "cloudwatch_alarms_active"),
]


def _signal_symptom_category(signal: RawSignal) -> str | None:
    for kinds, category in _SYMPTOM_CATEGORIES:
        if signal.kind in kinds:
            return category
    return None


def _symptom_description(category: str, signals: list[RawSignal]) -> str:
    services = sorted({s.service_name for s in signals})
    count = len(signals)
    descriptions = {
        "db_saturation": f"Database resource saturation across {', '.join(services)} ({count} signals)",
        "db_connectivity": f"Database connectivity errors on {', '.join(services)} ({count} signals)",
        "ecs_task_failures": f"ECS task failures on {', '.join(services)} ({count} signals)",
        "pod_oom_restarts": f"Pod OOM kills and restarts on {', '.join(services)} ({count} signals)",
        "host_resource_pressure": f"EC2 host resource pressure on {', '.join(services)} ({count} signals)",
        "lambda_execution_failures": f"Lambda execution failures on {', '.join(services)} ({count} signals)",
        "load_balancer_errors": f"ALB target errors on {', '.join(services)} ({count} signals)",
        "elevated_latency": f"Elevated latency detected on {', '.join(services)} ({count} signals)",
        "cloudwatch_alarms_active": f"CloudWatch alarms triggered on {', '.join(services)} ({count} signals)",
    }
    return descriptions.get(category, f"{category} symptoms ({count} signals)")
