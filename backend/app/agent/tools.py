"""Investigation agent tools — read-only CloudWatch access only."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from app.adapters.aws.factory import get_metrics_adapter
from app.agent.tool_schemas import (
    AnomalySummariesInput,
    AnomalySummariesOutput,
    CloudWatchMetricsInput,
    CloudWatchMetricsOutput,
    DeploymentMetadataInput,
    DeploymentMetadataOutput,
    DeploymentRecord,
    GroupedErrorPatternsInput,
    GroupedErrorPatternsOutput,
    PatternRow,
    SearchCloudWatchLogsInput,
    SearchCloudWatchLogsOutput,
)
from app.core.logging import get_logger
from app.intelligence.redaction import redact_for_ai
from app.schemas.logs import StartQueryRequest, TimeRange
from app.services.ingestion import LogIngestionService
from app.services.pattern_analysis import PatternAnalysisService

logger = get_logger(__name__)

_DEPLOY_RE = re.compile(
    r"(deploy(?:ment|ed|ing)?|rollout|release|version\s*=|image\s*tag)",
    re.IGNORECASE,
)
_VERSION_RE = re.compile(r"\b(v?\d+\.\d+\.\d+(?:-[\w.]+)?)\b")


class InvestigationTools:
    """Bounded, read-only tool implementations for the investigation agent."""

    def __init__(
        self,
        ingestion: LogIngestionService | None = None,
        analytics: PatternAnalysisService | None = None,
    ) -> None:
        self._ingestion = ingestion or LogIngestionService()
        self._analytics = analytics or PatternAnalysisService(ingestion=self._ingestion)

    async def dispatch(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if tool_name == "search_cloudwatch_logs":
            out = await self.search_cloudwatch_logs(SearchCloudWatchLogsInput.model_validate(arguments))
        elif tool_name == "get_grouped_error_patterns":
            out = await self.get_grouped_error_patterns(
                GroupedErrorPatternsInput.model_validate(arguments)
            )
        elif tool_name == "get_anomaly_summaries":
            out = await self.get_anomaly_summaries(AnomalySummariesInput.model_validate(arguments))
        elif tool_name == "get_cloudwatch_metrics":
            out = await self.get_cloudwatch_metrics(CloudWatchMetricsInput.model_validate(arguments))
        elif tool_name == "get_deployment_metadata":
            out = await self.get_deployment_metadata(
                DeploymentMetadataInput.model_validate(arguments)
            )
        else:
            raise ValueError(f"Unknown tool: {tool_name}")
        return out.model_dump(mode="json")

    async def search_cloudwatch_logs(
        self, params: SearchCloudWatchLogsInput
    ) -> SearchCloudWatchLogsOutput:
        tr = TimeRange(
            preset=params.time_range_preset,
            start_time=params.start_time,
            end_time=params.end_time,
        )
        request = StartQueryRequest(
            log_group_names=params.log_group_names,
            query_string=params.query_string,
            time_range=tr,
            limit=min(params.limit, 500),
            account_alias=params.account_alias,
        )
        started = await self._ingestion.start_query(request)
        result = await self._ingestion.poll_query_until_complete(
            started.query_id, account_alias=params.account_alias
        )
        events: list[dict[str, Any]] = []
        for ev in result.events[: params.limit]:
            events.append(
                {
                    "timestamp": ev.timestamp.isoformat(),
                    "message": redact_for_ai(ev.message),
                    "log_group": ev.log_group,
                    "log_stream": ev.log_stream,
                    "ptr": ev.ptr,
                }
            )
        return SearchCloudWatchLogsOutput(
            event_count=len(events),
            events=events,
            truncated=len(result.events) > len(events),
        )

    async def get_grouped_error_patterns(
        self, params: GroupedErrorPatternsInput
    ) -> GroupedErrorPatternsOutput:
        resp = await self._analytics.get_patterns(
            log_group_names=params.log_group_names,
            time_range_preset=params.time_range_preset,
            start_time=params.start_time,
            end_time=params.end_time,
            account_alias=params.account_alias,
            min_occurrences=params.min_occurrences,
            prefer_native=False,
        )
        rows: list[PatternRow] = []
        for p in resp.patterns[:50]:
            sev = p.severity.value if hasattr(p.severity, "value") else str(p.severity)
            if sev.upper() not in {"ERROR", "WARN", "WARNING", "CRITICAL", "FATAL"}:
                continue
            rows.append(
                PatternRow(
                    pattern=redact_for_ai(p.normalized_pattern[:500]),
                    occurrence_count=p.occurrence_count,
                    severity=sev,
                    sample_log_group=p.sample_log_group,
                )
            )
        return GroupedErrorPatternsOutput(pattern_count=len(rows), patterns=rows)

    async def get_anomaly_summaries(
        self, params: AnomalySummariesInput
    ) -> AnomalySummariesOutput:
        resp = await self._analytics.get_anomalies(
            log_group_names=params.log_group_names,
            time_range_preset=params.time_range_preset,
            start_time=params.start_time,
            end_time=params.end_time,
            bucket_minutes=params.bucket_minutes,
            account_alias=params.account_alias,
        )
        spikes = [
            {
                "bucket_start": s.bucket_start.isoformat(),
                "observed_value": s.observed_value,
                "baseline_mean": s.baseline_mean,
                "classification": str(s.classification),
                "is_incident": s.is_incident,
            }
            for s in (resp.error_rate_anomalies or [])[:20]
        ]
        warnings = [
            {
                "message_pattern": redact_for_ai(w.normalized_pattern[:200]),
                "periods_seen": w.periods_seen,
                "periods_total": w.periods_total,
            }
            for w in (resp.recurring_warnings or [])[:20]
        ]
        return AnomalySummariesOutput(
            status=str(resp.status),
            notes=list(resp.notes or [])[:10],
            error_rate_spikes=spikes,
            recurring_warnings=warnings,
        )

    async def get_cloudwatch_metrics(
        self, params: CloudWatchMetricsInput
    ) -> CloudWatchMetricsOutput:
        adapter = get_metrics_adapter()
        raw = await adapter.get_metric_data(params.metric_name, params.namespace)
        values = [float(v) for v in raw.get("values", [])[:100]]
        timestamps = [str(t) for t in raw.get("timestamps", [])[:100]]
        return CloudWatchMetricsOutput(
            namespace=params.namespace,
            metric_name=params.metric_name,
            datapoint_count=len(values),
            values=values,
            timestamps=timestamps,
        )

    async def get_deployment_metadata(
        self, params: DeploymentMetadataInput
    ) -> DeploymentMetadataOutput:
        query = (
            "fields @timestamp, @message, @logStream, @ptr, @logGroup "
            "| filter @message like /deploy|Deployment|rollout|version=/ "
            "| sort @timestamp desc "
            "| limit 50"
        )
        search = await self.search_cloudwatch_logs(
            SearchCloudWatchLogsInput(
                log_group_names=params.log_group_names,
                query_string=query,
                time_range_preset=params.time_range_preset,
                start_time=params.start_time,
                end_time=params.end_time,
                account_alias=params.account_alias,
                limit=50,
            )
        )
        deployments: list[DeploymentRecord] = []
        for ev in search.events:
            msg = ev.get("message", "")
            if not _DEPLOY_RE.search(msg):
                continue
            version = None
            vm = _VERSION_RE.search(msg)
            if vm:
                version = vm.group(1)
            ts_raw = ev.get("timestamp")
            deployed_at = None
            if ts_raw:
                try:
                    deployed_at = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
                except ValueError:
                    deployed_at = None
            service = params.service_name_hint or _service_from_log_group(ev.get("log_group", ""))
            deployments.append(
                DeploymentRecord(
                    service_name=service,
                    version=version,
                    deployed_at=deployed_at,
                    source="cloudwatch_logs",
                    excerpt=redact_for_ai(msg[:500]),
                    log_group=ev.get("log_group"),
                    ptr=ev.get("ptr"),
                )
            )
        return DeploymentMetadataOutput(
            deployment_count=len(deployments),
            deployments=deployments[:20],
        )


def _service_from_log_group(log_group: str) -> str:
    parts = log_group.strip("/").split("/")
    return parts[-1] if parts else log_group
