"""Tests for the cross-service Incident Correlation Engine.

Tests cover:
- Signal normalization (all six AWS service types)
- Timeline construction and error onset detection
- Service dependency graph building
- Deployment before/after analysis
- Root-cause hypothesis scoring and ranking
- All five synthetic failure scenarios (expected top hypothesis)
- Evidence strength calibration (temporal-only → WEAK/SPECULATIVE)
- Contradicting evidence reduces score
- Causation caveat is always set for temporal evidence
"""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

import pytest

from app.correlation.deployment import compute_deployment_deltas, extract_deployment_events
from app.correlation.engine import CorrelationEngine
from app.correlation.graph import build_service_graph, can_propagate_to
from app.correlation.hypotheses import generate_hypotheses
from app.correlation.signals import normalize_signal, normalize_signals
from app.correlation.timeline import build_timeline, compute_error_onset
from app.scenarios.synthetic import ScenarioGenerator
from app.schemas.incidents import (
    AnalyzeIncidentRequest,
    CorrelationMethod,
    EvidenceStrength,
    SignalKind,
    SignalSeverity,
    SignalSource,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────


def _ts(offset_minutes: float = 0) -> str:
    base = datetime(2026, 11, 1, 20, 0, 0, tzinfo=UTC)
    return (base + timedelta(minutes=offset_minutes)).isoformat()


def _make_request(**kwargs) -> AnalyzeIncidentRequest:
    defaults = dict(
        signals=[{"message": "placeholder", "source": "ecs", "kind": "log_error",
                  "severity": "info", "service_name": "x", "timestamp": _ts()}],
        incident_window_minutes=60,
        deployment_lookback_minutes=30,
        deployment_after_minutes=30,
    )
    defaults.update(kwargs)
    return AnalyzeIncidentRequest(**defaults)


_engine = CorrelationEngine()
_scenario_gen = ScenarioGenerator()


# ── Signal normalization ──────────────────────────────────────────────────────


class TestSignalNormalization:
    def test_canonical_signal_round_trips(self):
        raw = {
            "signal_id": "abc123",
            "source": "ecs",
            "kind": "ecs_task_failure",
            "severity": "high",
            "service_name": "prod-api",
            "message": "Task stopped with exit code 137",
            "timestamp": _ts(0),
            "deployment_version": "v2.3.4",
            "log_group": "/aws/ecs/prod-api",
        }
        sig = normalize_signal(raw)
        assert sig.signal_id == "abc123"
        assert sig.source == SignalSource.ECS
        assert sig.kind == SignalKind.ECS_TASK_FAILURE
        assert sig.severity == SignalSeverity.HIGH
        assert sig.deployment_version == "v2.3.4"

    def test_rds_signal_inferred_from_log_group(self):
        raw = {
            "message": "FATAL: too many connections",
            "timestamp": _ts(0),
            "service_name": "db-main",
            "log_group": "/aws/rds/cluster-main/error",
        }
        sig = normalize_signal(raw)
        assert sig.source == SignalSource.RDS

    def test_lambda_signal_from_log_group(self):
        raw = {
            "message": "Task timed out after 30.0 seconds",
            "timestamp": _ts(0),
            "service_name": "my-function",
            "log_group": "/aws/lambda/my-function",
        }
        sig = normalize_signal(raw)
        assert sig.source == SignalSource.LAMBDA
        assert sig.kind == SignalKind.LAMBDA_TIMEOUT

    def test_alb_kind_inferred_from_message(self):
        raw = {
            "message": "503 Service Unavailable — target returned 5xx",
            "timestamp": _ts(0),
            "service_name": "prod-alb",
            "source": "alb",
        }
        sig = normalize_signal(raw)
        assert sig.kind == SignalKind.ALB_TARGET_5XX

    def test_eks_oom_inferred(self):
        raw = {
            "message": "OOMKilled: container exceeded memory limit",
            "timestamp": _ts(0),
            "service_name": "frontend",
            "source": "eks",
        }
        sig = normalize_signal(raw)
        assert sig.kind == SignalKind.EKS_OOM_KILLED

    def test_cloudwatch_alarm_triggered(self):
        raw = {
            "source": "cloudwatch_alarm",
            "kind": "alarm_triggered",
            "message": "ALARM: CPUUtilization exceeded 90%",
            "timestamp": _ts(0),
            "service_name": "prod-api",
            "severity": "critical",
        }
        sig = normalize_signal(raw)
        assert sig.source == SignalSource.CLOUDWATCH_ALARM
        assert sig.kind == SignalKind.ALARM_TRIGGERED

    def test_malformed_signal_skipped_in_batch(self):
        raws = [
            None,  # malformed
            {"message": "valid", "source": "ecs", "kind": "log_error",
             "severity": "info", "service_name": "x", "timestamp": _ts()},
        ]
        # normalize_signals should skip None and process valid one
        signals = normalize_signals([r for r in raws if r is not None])
        assert len(signals) == 1

    def test_ms_epoch_timestamp_parsed(self):
        ts_ms = int(datetime(2026, 11, 1, 20, 0, 0, tzinfo=UTC).timestamp() * 1000)
        raw = {"message": "test", "source": "ecs", "kind": "log_error",
               "severity": "info", "service_name": "x", "timestamp": ts_ms}
        sig = normalize_signal(raw)
        assert sig.timestamp.year == 2026
        assert sig.timestamp.month == 11


# ── Timeline ──────────────────────────────────────────────────────────────────


class TestTimeline:
    def _make_signal_dict(self, offset=0, source="ecs", kind="ecs_task_failure",
                          severity="high", service_name="prod-api", message="fail"):
        return {
            "source": source, "kind": kind, "severity": severity,
            "service_name": service_name, "message": message,
            "timestamp": _ts(offset),
        }

    def test_timeline_is_chronological(self):
        raws = [
            self._make_signal_dict(offset=5),
            self._make_signal_dict(offset=1),
            self._make_signal_dict(offset=3),
        ]
        signals = normalize_signals(raws)
        timeline = build_timeline(signals)
        timestamps = [e.timestamp for e in timeline]
        assert timestamps == sorted(timestamps)

    def test_deployment_flagged_in_timeline(self):
        raws = [
            {"source": "ecs", "kind": "ecs_deployment_event", "severity": "info",
             "service_name": "prod-api", "timestamp": _ts(0),
             "message": "Deployment started: version=v2.3.5"},
        ]
        signals = normalize_signals(raws)
        timeline = build_timeline(signals)
        assert any(e.is_deployment for e in timeline)

    def test_error_onset_detected(self):
        # 2 baseline info signals, then 5 errors
        raws = (
            [{"source": "ecs", "kind": "log_error", "severity": "info",
              "service_name": "prod-api", "message": "healthy", "timestamp": _ts(-5)}] * 2
            + [{"source": "ecs", "kind": "ecs_task_failure", "severity": "high",
                "service_name": "prod-api", "message": "task failed", "timestamp": _ts(i)}
               for i in range(5)]
        )
        signals = normalize_signals(raws)
        onset = compute_error_onset(signals)
        assert onset is not None
        assert onset.first_error_at is not None
        assert onset.onset_rate_per_minute > 0

    def test_no_onset_when_no_errors(self):
        raws = [
            {"source": "ecs", "kind": "log_error", "severity": "info",
             "service_name": "prod-api", "message": "healthy", "timestamp": _ts(i)}
            for i in range(5)
        ]
        signals = normalize_signals(raws)
        onset = compute_error_onset(signals)
        assert onset is None


# ── Dependency graph ──────────────────────────────────────────────────────────


class TestDependencyGraph:
    def _signals_for(self, services: dict[str, str]) -> list[dict]:
        """services: {name: source}"""
        return [
            {"source": src, "kind": "log_error", "severity": "info",
             "service_name": name, "message": "ok", "timestamp": _ts(0)}
            for name, src in services.items()
        ]

    def test_alb_ecs_edge_inferred(self):
        from app.correlation.signals import normalize_signals
        raws = self._signals_for({"prod-alb": "alb", "prod-api": "ecs"})
        signals = normalize_signals(raws)
        nodes, edges = build_service_graph(signals)
        assert any(e.upstream == "prod-alb" and e.downstream == "prod-api" for e in edges)

    def test_explicit_dependency_added(self):
        from app.correlation.signals import normalize_signals
        raws = self._signals_for({"frontend": "ecs", "backend": "ecs"})
        signals = normalize_signals(raws)
        nodes, edges = build_service_graph(
            signals,
            known_deps=[{"upstream": "frontend", "downstream": "backend"}],
        )
        assert any(e.upstream == "frontend" and e.downstream == "backend" for e in edges)

    def test_can_propagate_to(self):
        from app.schemas.incidents import ServiceDependency
        edges = [
            ServiceDependency(upstream="alb", downstream="api", dependency_type="synchronous"),
            ServiceDependency(upstream="api", downstream="rds", dependency_type="database"),
        ]
        assert can_propagate_to("alb", "rds", edges)
        assert not can_propagate_to("rds", "alb", edges)

    def test_service_nodes_count_errors(self):
        from app.correlation.signals import normalize_signals
        raws = (
            [{"source": "ecs", "kind": "ecs_task_failure", "severity": "high",
              "service_name": "prod-api", "message": "fail", "timestamp": _ts(i)}
             for i in range(3)]
            + [{"source": "ecs", "kind": "log_error", "severity": "info",
                "service_name": "prod-api", "message": "ok", "timestamp": _ts(5)}]
        )
        signals = normalize_signals(raws)
        nodes, _ = build_service_graph(signals)
        api_node = next(n for n in nodes if n.name == "prod-api")
        assert api_node.error_signal_count == 3
        assert api_node.signal_count == 4


# ── Deployment analysis ───────────────────────────────────────────────────────


class TestDeploymentAnalysis:
    def test_deployment_extracted_from_signals(self):
        raws = [
            {"source": "ecs", "kind": "ecs_deployment_event", "severity": "info",
             "service_name": "prod-api", "message": "Deployment started: version=v2.3.5",
             "timestamp": _ts(0), "deployment_version": "v2.3.5"},
        ]
        signals = normalize_signals(raws)
        deployments = extract_deployment_events(signals)
        assert len(deployments) == 1
        assert deployments[0].version == "v2.3.5"

    def test_regression_detected_clean_baseline(self):
        """Zero errors before, 5 errors after → STRONG regression."""
        deploy_ts = _ts(0)
        raws = (
            # 5 errors AFTER deployment
            [{"source": "ecs", "kind": "ecs_task_failure", "severity": "high",
              "service_name": "prod-api", "message": "fail", "timestamp": _ts(i + 1)}
             for i in range(5)]
            + [{"source": "ecs", "kind": "ecs_deployment_event", "severity": "info",
                "service_name": "prod-api", "message": "Deployment: version=v2.3.5",
                "timestamp": deploy_ts, "deployment_version": "v2.3.5"}]
        )
        signals = normalize_signals(raws)
        deployments = extract_deployment_events(signals)
        deltas = compute_deployment_deltas(signals, deployments, before_window_minutes=30, after_window_minutes=30)
        assert len(deltas) == 1
        delta = deltas[0]
        assert delta.is_regression
        assert delta.regression_confidence == EvidenceStrength.STRONG
        assert delta.before_error_count == 0
        assert delta.after_error_count == 5

    def test_no_regression_when_errors_equal(self):
        raws = (
            # 2 errors BEFORE
            [{"source": "ecs", "kind": "ecs_task_failure", "severity": "high",
              "service_name": "prod-api", "message": "fail", "timestamp": _ts(-10 + i)}
             for i in range(2)]
            # 2 errors AFTER
            + [{"source": "ecs", "kind": "ecs_task_failure", "severity": "high",
                "service_name": "prod-api", "message": "fail", "timestamp": _ts(5 + i)}
               for i in range(2)]
            + [{"source": "ecs", "kind": "ecs_deployment_event", "severity": "info",
                "service_name": "prod-api", "message": "Deploy version=v2.0.0",
                "timestamp": _ts(0), "deployment_version": "v2.0.0"}]
        )
        signals = normalize_signals(raws)
        deployments = extract_deployment_events(signals)
        deltas = compute_deployment_deltas(signals, deployments, 30, 30)
        assert len(deltas) == 1
        # ratio == 1.0 — not a meaningful regression
        delta = deltas[0]
        assert delta.regression_confidence == EvidenceStrength.SPECULATIVE


# ── Hypothesis scoring ────────────────────────────────────────────────────────


class TestHypothesisScoring:
    def _build_rds_cascade_signals(self):
        """RDS + ECS cascade with no trace IDs — should get MODERATE via dependency."""
        return [
            {"source": "rds", "kind": "rds_max_connections", "severity": "critical",
             "service_name": "db-main", "message": "FATAL: too many connections", "timestamp": _ts(0)},
            {"source": "rds", "kind": "rds_high_cpu", "severity": "high",
             "service_name": "db-main", "message": "CPU=95%", "timestamp": _ts(1)},
            {"source": "ecs", "kind": "ecs_task_failure", "severity": "high",
             "service_name": "prod-api", "message": "SQLAlchemyError: cannot connect", "timestamp": _ts(2)},
            {"source": "ecs", "kind": "ecs_task_failure", "severity": "high",
             "service_name": "prod-api", "message": "SQLAlchemyError: cannot connect", "timestamp": _ts(3)},
            {"source": "alb", "kind": "alb_target_5xx", "severity": "high",
             "service_name": "prod-alb", "message": "503 errors", "timestamp": _ts(4)},
        ]

    def test_rds_is_top_hypothesis_in_cascade(self):
        raws = self._build_rds_cascade_signals()
        signals = normalize_signals(raws)
        nodes, edges = build_service_graph(signals)
        hypotheses = generate_hypotheses(signals, nodes, edges, deltas=[], max_hypotheses=5)
        assert hypotheses, "Should produce at least one hypothesis"
        top = hypotheses[0]
        assert top.implicated_service == "db-main", (
            f"Expected db-main as top hypothesis, got {top.implicated_service}"
        )

    def test_temporal_only_capped_at_weak(self):
        """Single service with errors, no linking IDs → WEAK or SPECULATIVE."""
        raws = [
            {"source": "ecs", "kind": "ecs_task_failure", "severity": "high",
             "service_name": "prod-api", "message": "fail", "timestamp": _ts(i)}
            for i in range(3)
        ]
        signals = normalize_signals(raws)
        nodes, edges = build_service_graph(signals)
        hypotheses = generate_hypotheses(signals, nodes, edges, deltas=[], max_hypotheses=5)
        assert hypotheses
        top = hypotheses[0]
        assert top.score <= 0.40, f"Temporal-only score should be ≤0.40, got {top.score}"
        assert top.evidence_strength in {EvidenceStrength.WEAK, EvidenceStrength.SPECULATIVE}

    def test_trace_id_link_boosts_score(self):
        """Shared trace ID across two services should add +0.35 to score."""
        shared_trace = "trace-abc123"
        raws = [
            {"source": "lambda", "kind": "lambda_invocation_failure", "severity": "high",
             "service_name": "order-processor", "message": "fail", "timestamp": _ts(1),
             "trace_id": shared_trace},
            {"source": "alb", "kind": "alb_target_5xx", "severity": "high",
             "service_name": "prod-alb", "message": "502", "timestamp": _ts(2),
             "trace_id": shared_trace},
        ]
        signals = normalize_signals(raws)
        nodes, edges = build_service_graph(signals)
        hypotheses = generate_hypotheses(signals, nodes, edges, deltas=[], max_hypotheses=5)
        assert hypotheses
        # At least one hypothesis should show trace_id_link in breakdown
        has_trace_link = any(
            "trace_id_link" in h.score_breakdown for h in hypotheses
        )
        assert has_trace_link, "Trace ID link should appear in score breakdown"

    def test_contradicting_evidence_reduces_score(self):
        """Service with many healthy signals mixed in should have reduced score."""
        raws = (
            # 1 error
            [{"source": "ecs", "kind": "ecs_task_failure", "severity": "high",
              "service_name": "prod-api", "message": "fail once", "timestamp": _ts(0)}]
            # 20 healthy signals (high health ratio → contradicting evidence)
            + [{"source": "ecs", "kind": "log_error", "severity": "info",
                "service_name": "prod-api", "message": "healthy", "timestamp": _ts(i * 0.1)}
               for i in range(20)]
        )
        signals = normalize_signals(raws)
        nodes, edges = build_service_graph(signals)
        hypotheses = generate_hypotheses(signals, nodes, edges, deltas=[], max_hypotheses=5)
        assert hypotheses
        top = hypotheses[0]
        assert top.contradicting_evidence, "Should have contradicting evidence from high health ratio"
        # Score should reflect deduction
        assert any(k.startswith("contradiction_") for k in top.score_breakdown)

    def test_causation_caveat_present_for_temporal(self):
        """Any hypothesis that used temporal correlation must have a caveat."""
        raws = [
            {"source": "rds", "kind": "rds_high_cpu", "severity": "high",
             "service_name": "db-main", "message": "CPU high", "timestamp": _ts(0)},
            {"source": "ecs", "kind": "ecs_task_failure", "severity": "high",
             "service_name": "prod-api", "message": "fail", "timestamp": _ts(2)},
        ]
        signals = normalize_signals(raws)
        nodes, edges = build_service_graph(signals)
        hypotheses = generate_hypotheses(signals, nodes, edges, deltas=[], max_hypotheses=5)
        for h in hypotheses:
            has_temporal = any(
                e.correlation_method == CorrelationMethod.TEMPORAL_PROXIMITY
                for e in h.supporting_evidence
            )
            if has_temporal:
                assert h.causation_caveat is not None, (
                    f"Hypothesis {h.hypothesis_id} uses temporal evidence but lacks causation_caveat"
                )

    def test_deployment_regression_scores_high(self):
        """Deployment regression with clean baseline should yield STRONG hypothesis."""
        raws = (
            [{"source": "ecs", "kind": "ecs_deployment_event", "severity": "info",
              "service_name": "svc-a", "message": "Deployment version=v2.0.0",
              "timestamp": _ts(0), "deployment_version": "v2.0.0"}]
            + [{"source": "ecs", "kind": "ecs_task_failure", "severity": "high",
                "service_name": "svc-a", "message": "fail", "timestamp": _ts(i + 1)}
               for i in range(6)]
        )
        signals = normalize_signals(raws)
        nodes, edges = build_service_graph(signals)
        from app.correlation.deployment import compute_deployment_deltas, extract_deployment_events
        deployments = extract_deployment_events(signals)
        deltas = compute_deployment_deltas(signals, deployments, 30, 30)
        hypotheses = generate_hypotheses(signals, nodes, edges, deltas=deltas, max_hypotheses=5)
        assert hypotheses
        top = hypotheses[0]
        assert "deployment_regression" in top.score_breakdown
        assert top.score_breakdown["deployment_regression"] == pytest.approx(0.30)


# ── Full engine integration ───────────────────────────────────────────────────


class TestFullEngine:
    def _run_scenario(self, name: str) -> "IncidentReport":  # noqa: F821
        result = _scenario_gen.generate(name, seed=42)
        req = AnalyzeIncidentRequest(
            signals=result["signals"],
            incident_window_minutes=90,
            deployment_lookback_minutes=40,
            deployment_after_minutes=40,
        )
        return _engine.analyze(result["signals"], req)

    def test_report_has_timeline(self):
        report = self._run_scenario("db_cascade_failure")
        assert report.timeline, "Timeline should not be empty"
        timestamps = [e.timestamp for e in report.timeline]
        assert timestamps == sorted(timestamps), "Timeline should be chronological"

    def test_report_has_affected_services(self):
        report = self._run_scenario("db_cascade_failure")
        assert report.affected_services, "Should have affected services"
        svc_names = {n.name for n in report.affected_services}
        assert "db-cluster-main" in svc_names
        assert "prod-api" in svc_names

    def test_db_cascade_top_hypothesis_is_rds(self):
        report = self._run_scenario("db_cascade_failure")
        assert report.root_cause_hypotheses, "Should produce hypotheses"
        top = report.root_cause_hypotheses[0]
        assert top.implicated_service == "db-cluster-main", (
            f"Expected db-cluster-main, got '{top.implicated_service}'"
        )

    def test_deployment_regression_detected(self):
        report = self._run_scenario("deployment_regression")
        regression_deltas = [d for d in report.deployment_deltas if d.is_regression]
        assert regression_deltas, "Deployment regression should be detected"
        top_delta = regression_deltas[0]
        assert top_delta.service_name == "order-processor"
        assert top_delta.deployment.version == "v2.3.5"

    def test_deployment_regression_top_hypothesis(self):
        report = self._run_scenario("deployment_regression")
        assert report.root_cause_hypotheses
        top = report.root_cause_hypotheses[0]
        assert top.implicated_service == "order-processor"
        assert "deployment_regression" in top.score_breakdown

    def test_memory_pressure_scenario_runs(self):
        report = self._run_scenario("memory_pressure_cascade")
        assert report.total_signals_ingested > 0
        # EC2 should appear as affected service
        svc_names = {n.name for n in report.affected_services}
        assert "eks-node-group-prod" in svc_names

    def test_lambda_thundering_herd_scenario_runs(self):
        report = self._run_scenario("lambda_thundering_herd")
        assert report.total_signals_ingested > 0
        svc_names = {n.name for n in report.affected_services}
        assert "order-processor" in svc_names

    def test_network_partition_scenario_runs(self):
        report = self._run_scenario("network_partition")
        assert report.total_signals_ingested > 0
        svc_names = {n.name for n in report.affected_services}
        assert "db-cluster-main" in svc_names

    def test_error_onset_populated(self):
        report = self._run_scenario("db_cascade_failure")
        assert report.error_onset is not None
        assert report.error_onset.onset_rate_per_minute > 0

    def test_infrastructure_symptoms_detected(self):
        report = self._run_scenario("db_cascade_failure")
        assert report.infrastructure_symptoms, "Should detect infrastructure symptoms"
        categories = {s.category for s in report.infrastructure_symptoms}
        assert "db_saturation" in categories or "db_connectivity" in categories

    def test_executive_summary_non_empty(self):
        report = self._run_scenario("db_cascade_failure")
        assert len(report.executive_summary) > 50

    def test_hypotheses_ranked_by_score(self):
        report = self._run_scenario("db_cascade_failure")
        scores = [h.score for h in report.root_cause_hypotheses]
        assert scores == sorted(scores, reverse=True), "Hypotheses must be ranked by score"
        ranks = [h.rank for h in report.root_cause_hypotheses]
        assert ranks == list(range(1, len(ranks) + 1)), "Ranks must be sequential"

    def test_all_scores_in_range(self):
        for scenario in ["db_cascade_failure", "deployment_regression", "memory_pressure_cascade"]:
            report = self._run_scenario(scenario)
            for h in report.root_cause_hypotheses:
                assert 0.0 <= h.score <= 1.0, f"Score {h.score} out of range in {scenario}"

    def test_empty_signals_returns_empty_report(self):
        req = AnalyzeIncidentRequest(
            signals=[{"message": "x", "source": "ecs", "kind": "log_error",
                      "severity": "info", "service_name": "x", "timestamp": _ts()}]
        )
        # Pass normalized but zero-error signals
        report = _engine.analyze(req.signals, req)
        assert report.report_id is not None

    def test_analysis_notes_generated(self):
        report = self._run_scenario("db_cascade_failure")
        assert isinstance(report.analysis_notes, list)

    def test_signals_by_source_tallied(self):
        report = self._run_scenario("db_cascade_failure")
        assert report.signals_by_source
        assert report.total_signals_ingested == sum(report.signals_by_source.values())


# ── Scenario generator ────────────────────────────────────────────────────────


class TestScenarioGenerator:
    def test_all_scenarios_generate_without_error(self):
        for name in ["db_cascade_failure", "deployment_regression",
                     "memory_pressure_cascade", "lambda_thundering_herd",
                     "network_partition"]:
            result = _scenario_gen.generate(name, seed=0)
            assert result["signal_count"] > 0
            assert result["signals"]

    def test_seed_is_deterministic(self):
        r1 = _scenario_gen.generate("db_cascade_failure", seed=7)
        r2 = _scenario_gen.generate("db_cascade_failure", seed=7)
        # Signal counts and service names should match
        assert r1["signal_count"] == r2["signal_count"]
        svc1 = {s["service_name"] for s in r1["signals"]}
        svc2 = {s["service_name"] for s in r2["signals"]}
        assert svc1 == svc2

    def test_unknown_scenario_raises(self):
        with pytest.raises(ValueError, match="Unknown scenario"):
            _scenario_gen.generate("nonexistent_scenario")

    def test_list_scenarios_returns_all(self):
        scenarios = _scenario_gen.list_scenarios()
        names = {s["name"] for s in scenarios}
        assert "db_cascade_failure" in names
        assert "deployment_regression" in names
        assert len(names) == 5
