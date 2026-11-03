"""Signal normalization — parse raw dicts into typed RawSignal objects.

Handles all supported AWS service event formats:
  - ECS task failures and deployment events
  - EKS pod restarts and application log errors
  - EC2 instance status checks and metric anomalies
  - Lambda invocation failures, timeouts, throttles
  - ALB target errors and latency metrics
  - RDS connection, CPU, and availability events
  - CloudWatch Alarm state changes
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any

from app.core.logging import get_logger
from app.schemas.incidents import (
    RawSignal,
    SignalKind,
    SignalSeverity,
    SignalSource,
)

logger = get_logger(__name__)

# ── Timestamp parsing ─────────────────────────────────────────────────────────

_ISO_TZ_RE = re.compile(r"Z$")


def _parse_timestamp(ts: Any) -> datetime:
    """Robustly parse a timestamp from various formats."""
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=UTC)
    if isinstance(ts, (int, float)):
        # Epoch seconds or milliseconds
        if ts > 1e10:
            ts = ts / 1000.0
        return datetime.fromtimestamp(ts, tz=UTC)
    if isinstance(ts, str):
        try:
            return datetime.fromisoformat(_ISO_TZ_RE.sub("+00:00", ts))
        except ValueError:
            pass
    return datetime.now(UTC)


# ── Severity mapping ──────────────────────────────────────────────────────────

_SEVERITY_MAP: dict[str, SignalSeverity] = {
    "critical": SignalSeverity.CRITICAL,
    "fatal": SignalSeverity.CRITICAL,
    "high": SignalSeverity.HIGH,
    "error": SignalSeverity.HIGH,
    "err": SignalSeverity.HIGH,
    "medium": SignalSeverity.MEDIUM,
    "warn": SignalSeverity.MEDIUM,
    "warning": SignalSeverity.MEDIUM,
    "low": SignalSeverity.LOW,
    "info": SignalSeverity.INFO,
    "information": SignalSeverity.INFO,
    "debug": SignalSeverity.INFO,
}


def _parse_severity(raw: Any) -> SignalSeverity:
    if isinstance(raw, str):
        return _SEVERITY_MAP.get(raw.lower(), SignalSeverity.MEDIUM)
    return SignalSeverity.MEDIUM


# ── Source / kind inference ───────────────────────────────────────────────────

_SOURCE_MAP: dict[str, SignalSource] = {
    "ecs": SignalSource.ECS,
    "eks": SignalSource.EKS,
    "ec2": SignalSource.EC2,
    "lambda": SignalSource.LAMBDA,
    "alb": SignalSource.ALB,
    "rds": SignalSource.RDS,
    "cloudwatch_alarm": SignalSource.CLOUDWATCH_ALARM,
    "cloudwatch": SignalSource.CLOUDWATCH_ALARM,
    "alarm": SignalSource.CLOUDWATCH_ALARM,
}

_KIND_MAP: dict[str, SignalKind] = {
    "ecs_task_failure": SignalKind.ECS_TASK_FAILURE,
    "task_failure": SignalKind.ECS_TASK_FAILURE,
    "ecs_deployment_event": SignalKind.ECS_DEPLOYMENT_EVENT,
    "deployment_event": SignalKind.ECS_DEPLOYMENT_EVENT,
    "deployment": SignalKind.ECS_DEPLOYMENT_EVENT,
    "ecs_service_degraded": SignalKind.ECS_SERVICE_DEGRADED,
    "eks_pod_restart": SignalKind.EKS_POD_RESTART,
    "pod_restart": SignalKind.EKS_POD_RESTART,
    "eks_app_log_error": SignalKind.EKS_APP_LOG_ERROR,
    "eks_oom_killed": SignalKind.EKS_OOM_KILLED,
    "oom_killed": SignalKind.EKS_OOM_KILLED,
    "ec2_metric_anomaly": SignalKind.EC2_METRIC_ANOMALY,
    "metric_anomaly": SignalKind.EC2_METRIC_ANOMALY,
    "ec2_status_check_failure": SignalKind.EC2_STATUS_CHECK_FAILURE,
    "status_check_failure": SignalKind.EC2_STATUS_CHECK_FAILURE,
    "lambda_invocation_failure": SignalKind.LAMBDA_INVOCATION_FAILURE,
    "invocation_failure": SignalKind.LAMBDA_INVOCATION_FAILURE,
    "lambda_timeout": SignalKind.LAMBDA_TIMEOUT,
    "timeout": SignalKind.LAMBDA_TIMEOUT,
    "lambda_error_rate": SignalKind.LAMBDA_ERROR_RATE,
    "lambda_throttle": SignalKind.LAMBDA_THROTTLE,
    "throttle": SignalKind.LAMBDA_THROTTLE,
    "alb_target_5xx": SignalKind.ALB_TARGET_5XX,
    "target_5xx": SignalKind.ALB_TARGET_5XX,
    "5xx": SignalKind.ALB_TARGET_5XX,
    "alb_high_latency": SignalKind.ALB_HIGH_LATENCY,
    "high_latency": SignalKind.ALB_HIGH_LATENCY,
    "alb_unhealthy_hosts": SignalKind.ALB_UNHEALTHY_HOSTS,
    "unhealthy_hosts": SignalKind.ALB_UNHEALTHY_HOSTS,
    "rds_connection_error": SignalKind.RDS_CONNECTION_ERROR,
    "connection_error": SignalKind.RDS_CONNECTION_ERROR,
    "rds_high_cpu": SignalKind.RDS_HIGH_CPU,
    "rds_availability_event": SignalKind.RDS_AVAILABILITY_EVENT,
    "rds_max_connections": SignalKind.RDS_MAX_CONNECTIONS,
    "max_connections": SignalKind.RDS_MAX_CONNECTIONS,
    "rds_replication_lag": SignalKind.RDS_REPLICATION_LAG,
    "alarm_triggered": SignalKind.ALARM_TRIGGERED,
    "alarm_state_triggered": SignalKind.ALARM_TRIGGERED,
    "alarm_resolved": SignalKind.ALARM_RESOLVED,
    "log_error": SignalKind.LOG_ERROR,
    "metric_spike": SignalKind.METRIC_SPIKE,
}


def _infer_source_from_log_group(log_group: str) -> SignalSource:
    """Guess the AWS service from the CloudWatch log group name."""
    lg = log_group.lower()
    if "/ecs/" in lg or lg.startswith("/aws/ecs"):
        return SignalSource.ECS
    if "/eks/" in lg or "kubernetes" in lg:
        return SignalSource.EKS
    if "/lambda/" in lg or lg.startswith("/aws/lambda"):
        return SignalSource.LAMBDA
    if "/rds/" in lg or "rds" in lg:
        return SignalSource.RDS
    if "alb" in lg or "elasticloadbalancing" in lg:
        return SignalSource.ALB
    if "/ec2/" in lg:
        return SignalSource.EC2
    return SignalSource.UNKNOWN


def _infer_kind_from_message(message: str, source: SignalSource) -> SignalKind:
    """Infer signal kind from message text when the 'kind' field is missing."""
    msg = message.lower()
    if source == SignalSource.ECS:
        if "deploy" in msg or "rollout" in msg:
            return SignalKind.ECS_DEPLOYMENT_EVENT
        if "task" in msg and ("fail" in msg or "stopped" in msg or "exit" in msg):
            return SignalKind.ECS_TASK_FAILURE
        return SignalKind.ECS_SERVICE_DEGRADED
    if source == SignalSource.EKS:
        if "oom" in msg or "out of memory" in msg or "killed" in msg:
            return SignalKind.EKS_OOM_KILLED
        if "restart" in msg or "crashloopbackoff" in msg:
            return SignalKind.EKS_POD_RESTART
        return SignalKind.EKS_APP_LOG_ERROR
    if source == SignalSource.LAMBDA:
        if "timeout" in msg or "timed out" in msg:
            return SignalKind.LAMBDA_TIMEOUT
        if "throttl" in msg:
            return SignalKind.LAMBDA_THROTTLE
        return SignalKind.LAMBDA_INVOCATION_FAILURE
    if source == SignalSource.ALB:
        if "latency" in msg or "response_time" in msg:
            return SignalKind.ALB_HIGH_LATENCY
        if "unhealthy" in msg:
            return SignalKind.ALB_UNHEALTHY_HOSTS
        return SignalKind.ALB_TARGET_5XX
    if source == SignalSource.RDS:
        if "cpu" in msg:
            return SignalKind.RDS_HIGH_CPU
        if "connection" in msg:
            return SignalKind.RDS_CONNECTION_ERROR
        if "max_connections" in msg or "too many connections" in msg:
            return SignalKind.RDS_MAX_CONNECTIONS
        return SignalKind.RDS_AVAILABILITY_EVENT
    if source == SignalSource.EC2:
        if "status" in msg and "check" in msg:
            return SignalKind.EC2_STATUS_CHECK_FAILURE
        return SignalKind.EC2_METRIC_ANOMALY
    if source == SignalSource.CLOUDWATCH_ALARM:
        if "ok" in msg or "resolved" in msg:
            return SignalKind.ALARM_RESOLVED
        return SignalKind.ALARM_TRIGGERED
    return SignalKind.LOG_ERROR


# ── Is this a deployment signal? ──────────────────────────────────────────────

DEPLOYMENT_KINDS: frozenset[SignalKind] = frozenset(
    {SignalKind.ECS_DEPLOYMENT_EVENT}
)


def is_deployment_signal(kind: SignalKind, message: str) -> bool:
    if kind in DEPLOYMENT_KINDS:
        return True
    msg = message.lower()
    return ("deploy" in msg or "rollout" in msg or "release" in msg) and (
        "version" in msg or "v2." in msg or "v1." in msg or "image" in msg
    )


# ── Main normalization function ───────────────────────────────────────────────


def normalize_signal(raw: dict[str, Any]) -> RawSignal:
    """Normalize an arbitrary dict into a typed RawSignal.

    Accepts:
    - Canonical RawSignal dicts (with 'source', 'kind' keys)
    - CloudWatch Logs Insights result rows (with '@message', '@timestamp')
    - AWS EventBridge / CloudWatch Alarm payloads
    - User-provided dicts for testing
    """
    # Signal ID
    signal_id = str(raw.get("signal_id", raw.get("id", str(uuid.uuid4())[:8])))

    # Timestamp
    timestamp = _parse_timestamp(
        raw.get("timestamp", raw.get("@timestamp", raw.get("time", raw.get("eventTime"))))
    )

    # Message
    message = str(
        raw.get("message", raw.get("@message", raw.get("detail", raw.get("description", ""))))
    )

    # Log group
    log_group: str | None = raw.get("log_group", raw.get("@logGroup", raw.get("logGroupName"))  )

    # Source
    raw_source = raw.get("source", raw.get("service_source", ""))
    if isinstance(raw_source, str) and raw_source.lower() in _SOURCE_MAP:
        source = _SOURCE_MAP[raw_source.lower()]
    elif log_group:
        source = _infer_source_from_log_group(log_group)
    else:
        # Try from service_name prefix
        svc = str(raw.get("service_name", "")).lower()
        if svc.startswith("rds") or "database" in svc:
            source = SignalSource.RDS
        elif svc.startswith("lambda") or svc.endswith("-lambda"):
            source = SignalSource.LAMBDA
        elif "alb" in svc or "loadbalancer" in svc:
            source = SignalSource.ALB
        else:
            source = SignalSource.UNKNOWN

    # Kind
    raw_kind = raw.get("kind", raw.get("event_type", raw.get("eventType", "")))
    if isinstance(raw_kind, str) and raw_kind.lower().replace("-", "_") in _KIND_MAP:
        kind = _KIND_MAP[raw_kind.lower().replace("-", "_")]
    else:
        kind = _infer_kind_from_message(message, source)

    # Severity
    severity = _parse_severity(
        raw.get("severity", raw.get("level", raw.get("@severityLabel")))
    )

    # Service name
    service_name = str(
        raw.get(
            "service_name",
            raw.get("serviceName", raw.get("clusterName", raw.get("functionName", "unknown"))),
        )
    )

    return RawSignal(
        signal_id=signal_id,
        source=source,
        kind=kind,
        severity=severity,
        timestamp=timestamp,
        service_name=service_name,
        resource_id=raw.get("resource_id", raw.get("resourceId", raw.get("taskArn"))),
        log_group=log_group,
        log_stream=raw.get("log_stream", raw.get("@logStream", raw.get("logStreamName"))),
        region=raw.get("region", raw.get("awsRegion", "us-east-1")),
        account_id=raw.get("account_id", raw.get("accountId")),
        trace_id=raw.get("trace_id", raw.get("traceId", raw.get("x_trace_id"))),
        request_id=raw.get("request_id", raw.get("requestId", raw.get("correlation_id"))),
        deployment_version=raw.get(
            "deployment_version",
            raw.get("version", raw.get("imageTag", raw.get("taskDefinitionRevision"))),
        ),
        message=message,
        metric_name=raw.get("metric_name", raw.get("metricName")),
        metric_value=_to_float(raw.get("metric_value", raw.get("metricValue"))),
        metric_unit=raw.get("metric_unit", raw.get("metricUnit")),
        evidence_ptr=raw.get("evidence_ptr", raw.get("@ptr", raw.get("ptr"))),
        raw_data={k: v for k, v in raw.items() if k not in _KNOWN_RAW_KEYS},
    )


def normalize_signals(raws: list[dict[str, Any]]) -> list[RawSignal]:
    """Normalize a batch of raw signal dicts, skipping unparseable items."""
    signals: list[RawSignal] = []
    for i, raw in enumerate(raws):
        try:
            signals.append(normalize_signal(raw))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Skipping malformed signal index=%d error=%s", i, exc)
    return signals


def _to_float(v: Any) -> float | None:
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


_KNOWN_RAW_KEYS = frozenset(
    {
        "signal_id", "id", "timestamp", "@timestamp", "time", "eventTime",
        "message", "@message", "detail", "description",
        "log_group", "@logGroup", "logGroupName",
        "source", "service_source",
        "kind", "event_type", "eventType",
        "severity", "level", "@severityLabel",
        "service_name", "serviceName", "clusterName", "functionName",
        "resource_id", "resourceId", "taskArn",
        "log_stream", "@logStream", "logStreamName",
        "region", "awsRegion",
        "account_id", "accountId",
        "trace_id", "traceId", "x_trace_id",
        "request_id", "requestId", "correlation_id",
        "deployment_version", "version", "imageTag", "taskDefinitionRevision",
        "metric_name", "metricName",
        "metric_value", "metricValue",
        "metric_unit", "metricUnit",
        "evidence_ptr", "@ptr", "ptr",
    }
)
