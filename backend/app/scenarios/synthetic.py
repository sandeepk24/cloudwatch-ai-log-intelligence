"""Synthetic multi-service failure scenarios for testing the Correlation Engine.

Each scenario generates a realistic time-ordered stream of RawSignal-compatible
dicts that exercise a specific failure pattern.  Scenarios are designed so that
the correlation engine should rank the intended root cause first.

Available scenarios:
  db_cascade_failure      — RDS CPU/connection saturation → ECS failures → ALB 5xx
  deployment_regression   — New ECS version → Lambda OOM → ALB latency spike
  memory_pressure_cascade — EC2 OOM → EKS pod evictions → service unavailability
  lambda_thundering_herd  — Traffic spike → Lambda concurrency exhaust → ALB 502s
  network_partition       — Transient RDS unreachable → multi-service connection errors
"""

from __future__ import annotations

import random
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

# ── Shared helpers ────────────────────────────────────────────────────────────


def _ts(base: datetime, offset_minutes: float, jitter_seconds: int = 0) -> str:
    """Return an ISO timestamp offset from base with optional jitter."""
    delta = timedelta(
        minutes=offset_minutes,
        seconds=random.randint(0, jitter_seconds) if jitter_seconds else 0,
    )
    return (base + delta).isoformat().replace("+00:00", "Z")


def _sid() -> str:
    return str(uuid.uuid4())[:8]


def _common(
    *,
    source: str,
    kind: str,
    severity: str,
    service_name: str,
    message: str,
    timestamp: str,
    **extra: Any,
) -> dict[str, Any]:
    return {
        "signal_id": _sid(),
        "source": source,
        "kind": kind,
        "severity": severity,
        "service_name": service_name,
        "message": message,
        "timestamp": timestamp,
        **extra,
    }


# ── Scenario 1: DB Cascade Failure ───────────────────────────────────────────
#
# Root cause: RDS CPU saturation → max_connections exhausted
# Propagation path: RDS → ECS prod-api → ALB → CloudWatch alarm
#
# Expected:
#   - Top hypothesis: RDS saturation (db_saturation symptom + dependency graph)
#   - No deployment regression (no deploy events)
#   - MODERATE confidence (temporal + dependency, no trace IDs)


def _db_cascade_failure(base: datetime, rng: random.Random) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []

    # T-30: Healthy baseline signals
    for i in range(5):
        signals.append(
            _common(
                source="ecs", kind="log_error", severity="info",
                service_name="prod-api",
                message="Health check passed: status=healthy uptime=12h",
                timestamp=_ts(base, -30 + i * 5, 30),
                log_group="/aws/ecs/prod-api",
            )
        )

    # T+0: RDS CPU starts climbing
    signals.append(
        _common(
            source="rds", kind="rds_high_cpu", severity="medium",
            service_name="db-cluster-main",
            message="RDS CPU utilization reached 78% — above warning threshold of 70%",
            timestamp=_ts(base, 0, 10),
            metric_name="CPUUtilization", metric_value=78.0, metric_unit="%",
            resource_id="arn:aws:rds:us-east-1:123456789012:cluster:db-cluster-main",
            log_group="/aws/rds/cluster-main/slowquery",
        )
    )

    # T+2: RDS CPU peaks at 96%
    signals.append(
        _common(
            source="rds", kind="rds_high_cpu", severity="high",
            service_name="db-cluster-main",
            message="RDS CPU utilization peaked at 96% — slow query storm detected",
            timestamp=_ts(base, 2, 15),
            metric_name="CPUUtilization", metric_value=96.0, metric_unit="%",
            resource_id="arn:aws:rds:us-east-1:123456789012:cluster:db-cluster-main",
            log_group="/aws/rds/cluster-main/slowquery",
        )
    )

    # T+3: Max connections reached
    for i in range(3):
        signals.append(
            _common(
                source="rds", kind="rds_max_connections", severity="critical",
                service_name="db-cluster-main",
                message="FATAL: remaining connection slots are reserved for non-replication superuser connections",
                timestamp=_ts(base, 3 + i * 0.5, 10),
                metric_name="DatabaseConnections", metric_value=500.0, metric_unit="Count",
                resource_id="arn:aws:rds:us-east-1:123456789012:cluster:db-cluster-main",
                log_group="/aws/rds/cluster-main/error",
            )
        )

    # T+3.5: ECS tasks start failing with connection errors
    for i in range(6):
        signals.append(
            _common(
                source="ecs", kind="ecs_task_failure", severity="high",
                service_name="prod-api",
                message=(
                    "Task stopped: CannotPullContainerError — "
                    "SQLAlchemyError: could not connect to server: Connection refused "
                    f"(attempt {i+1}, task_id=task-{rng.randint(1000,9999)})"
                ),
                timestamp=_ts(base, 3.5 + i * 0.5, 20),
                log_group="/aws/ecs/prod-api",
                resource_id=f"arn:aws:ecs:us-east-1:123456789012:task/prod-api/{_sid()}",
            )
        )

    # T+4: ALB starts seeing 5xx
    for i in range(4):
        signals.append(
            _common(
                source="alb", kind="alb_target_5xx", severity="high",
                service_name="prod-alb",
                message=f"Target group tg-prod-api: 503 Service Unavailable — {rng.randint(15,45)} requests affected",
                timestamp=_ts(base, 4 + i * 0.5, 15),
                metric_name="HTTPCode_Target_5XX_Count", metric_value=float(rng.randint(15,45)),
                log_group="/aws/elasticloadbalancing/prod-alb",
            )
        )

    # T+4.5: EKS pods also calling RDS start failing
    for i in range(3):
        signals.append(
            _common(
                source="eks", kind="eks_app_log_error", severity="high",
                service_name="data-processor",
                message="psycopg2.OperationalError: FATAL: remaining connection slots reserved for superuser",
                timestamp=_ts(base, 4.5 + i * 0.5, 15),
                log_group="/aws/eks/prod-cluster/data-processor",
            )
        )

    # T+5: ALB unhealthy hosts rising
    signals.append(
        _common(
            source="alb", kind="alb_unhealthy_hosts", severity="critical",
            service_name="prod-alb",
            message="TargetGroup tg-prod-api: UnhealthyHostCount=3 HealthyHostCount=1 — service degraded",
            timestamp=_ts(base, 5, 10),
            metric_name="UnHealthyHostCount", metric_value=3.0, metric_unit="Count",
        )
    )

    # T+5.5: CloudWatch alarm triggers
    signals.append(
        _common(
            source="cloudwatch_alarm", kind="alarm_triggered", severity="critical",
            service_name="prod-api",
            message="ALARM: prod-api-5xx-rate exceeded threshold — AlarmName=prod-api-HighErrorRate State=ALARM",
            timestamp=_ts(base, 5.5, 5),
            metric_name="HTTPCode_Target_5XX_Count",
            log_group=None,
        )
    )
    signals.append(
        _common(
            source="cloudwatch_alarm", kind="alarm_triggered", severity="critical",
            service_name="db-cluster-main",
            message="ALARM: RDS-MaxConnections exceeded — AlarmName=rds-max-connections State=ALARM",
            timestamp=_ts(base, 5.5, 10),
            metric_name="DatabaseConnections",
        )
    )

    # T+8: Lambda payment processor also affected
    for i in range(2):
        signals.append(
            _common(
                source="lambda", kind="lambda_invocation_failure", severity="high",
                service_name="payment-processor",
                message="Task timed out after 29.9 seconds — SQLAlchemy: QueuePool limit overflow, connection timed out",
                timestamp=_ts(base, 8 + i, 20),
                log_group="/aws/lambda/payment-processor",
            )
        )

    return sorted(signals, key=lambda s: s["timestamp"])


# ── Scenario 2: Deployment Regression ────────────────────────────────────────
#
# Root cause: v2.3.5 introduced memory leak → Lambda OOM → ALB latency
# Propagation: deployment → Lambda timeout → ALB 502 → alarm
#
# Expected:
#   - Top hypothesis: deployment regression (STRONG if version matches)
#   - DeploymentDelta showing clean baseline, errors after deploy


def _deployment_regression(base: datetime, rng: random.Random) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    new_version = "v2.3.5"
    old_version = "v2.3.4"

    # T-30: Healthy baseline under old version
    for i in range(6):
        signals.append(
            _common(
                source="lambda", kind="log_error", severity="info",
                service_name="order-processor",
                message=f"REPORT RequestId: {_sid()} Duration: {rng.randint(80,250)}ms Billed Duration: {rng.randint(100,300)}ms",
                timestamp=_ts(base, -30 + i * 5, 30),
                deployment_version=old_version,
                log_group="/aws/lambda/order-processor",
            )
        )
    for i in range(3):
        signals.append(
            _common(
                source="alb", kind="log_error", severity="info",
                service_name="prod-alb",
                message=f"GET /api/v1/orders HTTP/1.1 200 - {rng.randint(80,200)}ms",
                timestamp=_ts(base, -25 + i * 5, 30),
                metric_name="TargetResponseTime", metric_value=float(rng.randint(80,200)) / 1000,
            )
        )

    # T+0: Deployment of v2.3.5
    deploy_trace = _sid()
    signals.append(
        _common(
            source="ecs", kind="ecs_deployment_event", severity="info",
            service_name="order-processor",
            message=f"Deployment started: service=order-processor version={new_version} replicas=3 strategy=rolling",
            timestamp=_ts(base, 0, 5),
            deployment_version=new_version,
            trace_id=deploy_trace,
            log_group="/aws/ecs/prod-api",
            resource_id="arn:aws:ecs:us-east-1:123456789012:service/prod/order-processor",
        )
    )
    signals.append(
        _common(
            source="ecs", kind="ecs_deployment_event", severity="info",
            service_name="order-processor",
            message=f"Deployment complete: version={new_version} all tasks healthy",
            timestamp=_ts(base, 2, 10),
            deployment_version=new_version,
            trace_id=deploy_trace,
            log_group="/aws/ecs/prod-api",
        )
    )

    # T+3: Lambda starts timing out (memory leak fills up, GC pauses extend duration)
    for i in range(5):
        req_id = _sid()
        signals.append(
            _common(
                source="lambda", kind="lambda_timeout", severity="high",
                service_name="order-processor",
                message=(
                    f"Task timed out after 30.0 seconds — "
                    f"RequestId: {req_id} "
                    f"Memory Used: {rng.randint(490,510)}MB / 512MB"
                ),
                timestamp=_ts(base, 3 + i * 0.7, 20),
                deployment_version=new_version,
                request_id=req_id,
                log_group="/aws/lambda/order-processor",
                metric_name="Duration", metric_value=30000.0, metric_unit="ms",
            )
        )

    # T+4: Lambda error rate alarm
    signals.append(
        _common(
            source="lambda", kind="lambda_error_rate", severity="high",
            service_name="order-processor",
            message=f"ErrorRate=34.5% for order-processor:{new_version} — exceeds 5% threshold",
            timestamp=_ts(base, 4, 10),
            deployment_version=new_version,
            metric_name="Errors", metric_value=34.5, metric_unit="%",
            log_group="/aws/lambda/order-processor",
        )
    )

    # T+4.5: ECS tasks OOM-killed (memory leak → container restart)
    for i in range(4):
        signals.append(
            _common(
                source="ecs", kind="ecs_task_failure", severity="high",
                service_name="order-processor",
                message=f"Task stopped — reason: Essential container exited, exit code: 137 (OOM) version={new_version}",
                timestamp=_ts(base, 4.5 + i * 0.5, 20),
                deployment_version=new_version,
                log_group="/aws/ecs/prod-api",
            )
        )

    # T+5: ALB latency spikes
    for i in range(4):
        signals.append(
            _common(
                source="alb", kind="alb_high_latency", severity="medium",
                service_name="prod-alb",
                message=f"TargetResponseTime P99={rng.randint(4500,8000)}ms — SLO breach (threshold 1000ms)",
                timestamp=_ts(base, 5 + i * 0.5, 15),
                metric_name="TargetResponseTime", metric_value=float(rng.randint(4500,8000)) / 1000,
                metric_unit="s",
            )
        )

    # T+5.5: ALB 5xx from Lambda integration errors
    for i in range(3):
        signals.append(
            _common(
                source="alb", kind="alb_target_5xx", severity="high",
                service_name="prod-alb",
                message="Lambda integration returned 502 Bad Gateway — timeout or crash",
                timestamp=_ts(base, 5.5 + i * 0.5, 10),
                metric_name="HTTPCode_ELB_5XX_Count", metric_value=float(rng.randint(10,30)),
            )
        )

    # T+6: CloudWatch alarms
    signals.append(
        _common(
            source="cloudwatch_alarm", kind="alarm_triggered", severity="critical",
            service_name="order-processor",
            message=f"ALARM: LambdaErrorRate — order-processor error rate exceeded 10% threshold",
            timestamp=_ts(base, 6, 5),
        )
    )

    return sorted(signals, key=lambda s: s["timestamp"])


# ── Scenario 3: Memory Pressure Cascade ──────────────────────────────────────
#
# Root cause: EC2 node memory exhaustion → EKS pod OOM evictions
# Propagation: EC2 host → EKS pods → service unavailability → ALB errors
#
# Expected:
#   - Top hypothesis: EC2 memory pressure (dependency + temporal)
#   - No deployment regression


def _memory_pressure_cascade(base: datetime, rng: random.Random) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    node_id = "i-0abc123def456789a"

    # T+0: EC2 memory pressure building
    for i in range(3):
        signals.append(
            _common(
                source="ec2", kind="ec2_metric_anomaly", severity="medium",
                service_name="eks-node-group-prod",
                message=f"mem_used_percent={82 + i*3}% on {node_id} — above warning threshold 80%",
                timestamp=_ts(base, i * 1.5, 20),
                metric_name="mem_used_percent", metric_value=float(82 + i * 3), metric_unit="%",
                resource_id=node_id,
            )
        )

    # T+3: EC2 memory critical
    signals.append(
        _common(
            source="ec2", kind="ec2_metric_anomaly", severity="critical",
            service_name="eks-node-group-prod",
            message=f"mem_used_percent=97% — kernel OOM killer likely to activate on {node_id}",
            timestamp=_ts(base, 3, 10),
            metric_name="mem_used_percent", metric_value=97.0, metric_unit="%",
            resource_id=node_id,
        )
    )

    # T+3.5: EKS pods OOM-killed
    for pod, svc in [("frontend-5d8b9f-xkp2t", "frontend"), ("api-gateway-7c6d-lp4nq", "api-gateway")]:
        for i in range(2):
            signals.append(
                _common(
                    source="eks", kind="eks_oom_killed", severity="high",
                    service_name=svc,
                    message=f"OOMKilled: Container {svc} exceeded memory limit 512Mi on node {node_id}, pod {pod}",
                    timestamp=_ts(base, 3.5 + i * 0.5, 15),
                    log_group=f"/aws/eks/prod-cluster/{svc}",
                    resource_id=f"pod/{pod}",
                )
            )

    # T+4: Pod restart loop
    for svc in ["frontend", "api-gateway"]:
        for i in range(3):
            signals.append(
                _common(
                    source="eks", kind="eks_pod_restart", severity="medium",
                    service_name=svc,
                    message=f"Pod restarting (CrashLoopBackOff): {svc} restart count={i+1}",
                    timestamp=_ts(base, 4 + i * 0.5, 20),
                    log_group=f"/aws/eks/prod-cluster/{svc}",
                )
            )

    # T+5: EC2 status check failure
    signals.append(
        _common(
            source="ec2", kind="ec2_status_check_failure", severity="critical",
            service_name="eks-node-group-prod",
            message=f"Instance status check failed for {node_id}: SystemStatusCheckFailed",
            timestamp=_ts(base, 5, 10),
            resource_id=node_id,
        )
    )

    # T+5.5: ALB sees unhealthy hosts
    for i in range(3):
        signals.append(
            _common(
                source="alb", kind="alb_unhealthy_hosts", severity="high",
                service_name="prod-alb",
                message=f"UnhealthyHostCount={i+2} — pods not passing health checks after OOM restart",
                timestamp=_ts(base, 5.5 + i * 0.5, 10),
                metric_name="UnHealthyHostCount", metric_value=float(i+2),
            )
        )

    # T+6: ALB 5xx
    for i in range(3):
        signals.append(
            _common(
                source="alb", kind="alb_target_5xx", severity="high",
                service_name="prod-alb",
                message=f"503 Service Unavailable — no healthy targets in tg-frontend ({rng.randint(20,60)} req affected)",
                timestamp=_ts(base, 6 + i * 0.3, 15),
                metric_name="HTTPCode_Target_5XX_Count", metric_value=float(rng.randint(20,60)),
            )
        )

    # T+7: Alarm
    signals.append(
        _common(
            source="cloudwatch_alarm", kind="alarm_triggered", severity="critical",
            service_name="eks-node-group-prod",
            message="ALARM: EKS-NodeMemoryPressure — mem_used_percent exceeded 90% threshold",
            timestamp=_ts(base, 7, 5),
            metric_name="mem_used_percent",
        )
    )

    return sorted(signals, key=lambda s: s["timestamp"])


# ── Scenario 4: Lambda Thundering Herd ───────────────────────────────────────
#
# Root cause: Traffic spike → Lambda concurrency exhaustion → throttles → ALB 502s
#
# Expected:
#   - Top hypothesis: Lambda throttling (alarm + metric signals)
#   - No deployment regression


def _lambda_thundering_herd(base: datetime, rng: random.Random) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []

    # T+0: ALB request count spikes (detected as metric anomaly)
    signals.append(
        _common(
            source="alb", kind="metric_spike", severity="medium",
            service_name="prod-alb",
            message="RequestCount spike: 45,000 req/min — 8× baseline (5,500 req/min)",
            timestamp=_ts(base, 0, 10),
            metric_name="RequestCount", metric_value=45000.0, metric_unit="Count/min",
        )
    )

    # T+1: Lambda cold starts (init duration logged)
    for i in range(4):
        signals.append(
            _common(
                source="lambda", kind="lambda_invocation_failure", severity="medium",
                service_name="order-processor",
                message=f"Init Duration: {rng.randint(1200,3000)}ms — cold start from concurrency surge",
                timestamp=_ts(base, 1 + i * 0.3, 20),
                log_group="/aws/lambda/order-processor",
                metric_name="InitDuration", metric_value=float(rng.randint(1200,3000)), metric_unit="ms",
            )
        )

    # T+2: Lambda throttles (concurrency limit hit)
    for i in range(6):
        req_id = _sid()
        signals.append(
            _common(
                source="lambda", kind="lambda_throttle", severity="high",
                service_name="order-processor",
                message=f"Rate Exceeded — RequestId: {req_id} — ReservedConcurrencyLimit=100 reached",
                timestamp=_ts(base, 2 + i * 0.4, 15),
                request_id=req_id,
                log_group="/aws/lambda/order-processor",
                metric_name="Throttles", metric_value=float(rng.randint(50,150)),
            )
        )

    # T+2: notification-sender also throttled (downstream)
    for i in range(3):
        signals.append(
            _common(
                source="lambda", kind="lambda_throttle", severity="high",
                service_name="notification-sender",
                message=f"Lambda function throttled — concurrency limit reached",
                timestamp=_ts(base, 2.5 + i * 0.4, 15),
                log_group="/aws/lambda/notification-sender",
                metric_name="Throttles", metric_value=float(rng.randint(20,60)),
            )
        )

    # T+3: ALB 502s from Lambda integration errors
    for i in range(5):
        signals.append(
            _common(
                source="alb", kind="alb_target_5xx", severity="critical",
                service_name="prod-alb",
                message=f"502 Bad Gateway — Lambda integration error (throttled) {rng.randint(100,300)} requests",
                timestamp=_ts(base, 3 + i * 0.4, 10),
                metric_name="HTTPCode_ELB_5XX_Count", metric_value=float(rng.randint(100,300)),
            )
        )

    # T+4: Lambda timeout alarms
    signals.append(
        _common(
            source="cloudwatch_alarm", kind="alarm_triggered", severity="critical",
            service_name="order-processor",
            message="ALARM: LambdaThrottles — order-processor throttle rate exceeded threshold",
            timestamp=_ts(base, 4, 5),
            metric_name="Throttles",
        )
    )
    signals.append(
        _common(
            source="cloudwatch_alarm", kind="alarm_triggered", severity="critical",
            service_name="prod-alb",
            message="ALARM: ALB-5xxRate — 5xx rate exceeded 10% threshold",
            timestamp=_ts(base, 4.5, 5),
            metric_name="HTTPCode_ELB_5XX_Count",
        )
    )

    return sorted(signals, key=lambda s: s["timestamp"])


# ── Scenario 5: Network Partition (RDS Unreachable) ──────────────────────────
#
# Root cause: Transient network partition isolating RDS → all services fail to connect
# No deployment, no version change
#
# Expected:
#   - Top hypothesis: RDS connectivity (multiple services affected via dependency)
#   - MODERATE confidence (dependency + temporal, no trace IDs)


def _network_partition(base: datetime, rng: random.Random) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []

    # T+0: RDS becomes unreachable
    signals.append(
        _common(
            source="rds", kind="rds_availability_event", severity="critical",
            service_name="db-cluster-main",
            message="RDS MultiAZ failover started — primary node unresponsive, initiating failover to replica",
            timestamp=_ts(base, 0, 5),
            resource_id="arn:aws:rds:us-east-1:123456789012:cluster:db-cluster-main",
            log_group="/aws/rds/cluster-main/error",
        )
    )

    # T+0.5 to T+3: Multiple services start getting connection errors simultaneously
    for svc, src in [
        ("prod-api", "ecs"),
        ("data-processor", "eks"),
        ("payment-processor", "lambda"),
        ("order-processor", "lambda"),
    ]:
        for i in range(3):
            signals.append(
                _common(
                    source=src, kind="rds_connection_error", severity="high",
                    service_name=svc,
                    message=(
                        f"OperationalError: could not connect to server: Connection refused "
                        f"Is the server running on host 'db-cluster-main.us-east-1.rds.amazonaws.com' "
                        f"and accepting TCP/IP connections on port 5432? (attempt {i+1})"
                    ),
                    timestamp=_ts(base, 0.5 + i * 0.5, 30),
                    log_group=f"/aws/{src}/{svc}",
                )
            )

    # T+2: RDS connection error metric
    signals.append(
        _common(
            source="rds", kind="rds_connection_error", severity="critical",
            service_name="db-cluster-main",
            message="DatabaseConnections dropped to 0 — all clients disconnected during failover",
            timestamp=_ts(base, 2, 10),
            metric_name="DatabaseConnections", metric_value=0.0, metric_unit="Count",
        )
    )

    # T+3: ALB 503s (all backends returning errors)
    for i in range(4):
        signals.append(
            _common(
                source="alb", kind="alb_target_5xx", severity="critical",
                service_name="prod-alb",
                message=f"503 Service Unavailable — all targets returning DB connection errors ({rng.randint(50,150)} reqs)",
                timestamp=_ts(base, 3 + i * 0.5, 10),
                metric_name="HTTPCode_Target_5XX_Count", metric_value=float(rng.randint(50,150)),
            )
        )

    # T+4: Alarms
    signals.append(
        _common(
            source="cloudwatch_alarm", kind="alarm_triggered", severity="critical",
            service_name="db-cluster-main",
            message="ALARM: RDS-DatabaseConnections — connections dropped below 10",
            timestamp=_ts(base, 4, 5),
            metric_name="DatabaseConnections",
        )
    )

    # T+6: RDS failover complete, connections recovering
    signals.append(
        _common(
            source="rds", kind="rds_availability_event", severity="info",
            service_name="db-cluster-main",
            message="RDS MultiAZ failover complete — new primary endpoint active, accepting connections",
            timestamp=_ts(base, 6, 10),
        )
    )
    signals.append(
        _common(
            source="cloudwatch_alarm", kind="alarm_resolved", severity="info",
            service_name="db-cluster-main",
            message="OK: RDS-DatabaseConnections — connections recovered to normal level",
            timestamp=_ts(base, 7, 5),
            metric_name="DatabaseConnections",
        )
    )

    return sorted(signals, key=lambda s: s["timestamp"])


# ── Registry ──────────────────────────────────────────────────────────────────


class ScenarioMeta:
    def __init__(
        self,
        name: str,
        description: str,
        generator,
        expected_root_cause: str,
        expected_deployment_regression: bool,
    ):
        self.name = name
        self.description = description
        self.generator = generator
        self.expected_root_cause = expected_root_cause
        self.expected_deployment_regression = expected_deployment_regression


SCENARIO_REGISTRY: dict[str, ScenarioMeta] = {
    "db_cascade_failure": ScenarioMeta(
        name="db_cascade_failure",
        description=(
            "RDS CPU saturation and connection pool exhaustion cascades to ECS task failures, "
            "ALB 5xx errors, and CloudWatch alarms. "
            "Tests dependency-based root cause attribution without trace IDs."
        ),
        generator=_db_cascade_failure,
        expected_root_cause="Database saturation in db-cluster-main",
        expected_deployment_regression=False,
    ),
    "deployment_regression": ScenarioMeta(
        name="deployment_regression",
        description=(
            "A new ECS deployment (v2.3.5) introduces a memory leak in order-processor. "
            "Lambda timeouts and OOM kills follow. Before/after deployment delta "
            "provides STRONG regression evidence."
        ),
        generator=_deployment_regression,
        expected_root_cause="Deployment regression in order-processor (v2.3.5)",
        expected_deployment_regression=True,
    ),
    "memory_pressure_cascade": ScenarioMeta(
        name="memory_pressure_cascade",
        description=(
            "EC2 node memory exhaustion triggers EKS pod OOM evictions across multiple services. "
            "Tests host-level symptom detection propagating to ALB errors."
        ),
        generator=_memory_pressure_cascade,
        expected_root_cause="EC2 host memory exhaustion on eks-node-group-prod",
        expected_deployment_regression=False,
    ),
    "lambda_thundering_herd": ScenarioMeta(
        name="lambda_thundering_herd",
        description=(
            "A traffic spike saturates Lambda reserved concurrency, causing throttles "
            "and ALB 502 errors. Tests Lambda concurrency exhaustion pattern detection."
        ),
        generator=_lambda_thundering_herd,
        expected_root_cause="Lambda concurrency exhaustion in order-processor",
        expected_deployment_regression=False,
    ),
    "network_partition": ScenarioMeta(
        name="network_partition",
        description=(
            "Transient RDS MultiAZ failover causes simultaneous connection errors across "
            "four services. Tests multi-service DB dependency attribution with recovery signals."
        ),
        generator=_network_partition,
        expected_root_cause="RDS availability event in db-cluster-main",
        expected_deployment_regression=False,
    ),
}


class ScenarioGenerator:
    """Generate synthetic failure scenario signals."""

    def generate(self, scenario_name: str, seed: int | None = None) -> dict[str, Any]:
        """Generate signals for the named scenario.

        Returns a dict with keys:
          scenario_name, description, signals, expected_root_cause,
          expected_deployment_regression, signal_count
        """
        if scenario_name not in SCENARIO_REGISTRY:
            available = ", ".join(SCENARIO_REGISTRY.keys())
            raise ValueError(
                f"Unknown scenario '{scenario_name}'. Available: {available}"
            )

        meta = SCENARIO_REGISTRY[scenario_name]
        rng = random.Random(seed)
        base = datetime.now(UTC).replace(microsecond=0)

        signals = meta.generator(base, rng)

        return {
            "scenario_name": scenario_name,
            "description": meta.description,
            "signals": signals,
            "expected_root_cause": meta.expected_root_cause,
            "expected_deployment_regression": meta.expected_deployment_regression,
            "signal_count": len(signals),
        }

    def list_scenarios(self) -> list[dict[str, Any]]:
        """List all available scenarios with metadata."""
        return [
            {
                "name": meta.name,
                "description": meta.description,
                "expected_root_cause": meta.expected_root_cause,
                "expected_deployment_regression": meta.expected_deployment_regression,
            }
            for meta in SCENARIO_REGISTRY.values()
        ]
