"""Canned CloudWatch responses for local development. No AWS calls."""

from __future__ import annotations

from typing import Any

from app.core.logging import get_logger

logger = get_logger(__name__)

MOCK_LOG_GROUPS: list[dict[str, Any]] = [
    {
        "logGroupName": "/aws/ecs/sample-api",
        "storedBytes": 1_048_576,
        "retentionInDays": 14,
    },
    {
        "logGroupName": "/aws/lambda/sample-worker",
        "storedBytes": 524_288,
        "retentionInDays": 7,
    },
    {
        "logGroupName": "/aws/apigateway/sample",
        "storedBytes": 262_144,
        "retentionInDays": 30,
    },
]

MOCK_QUERY_ROWS: list[dict[str, Any]] = [
    {
        "timestamp": "2026-10-30T18:01:12Z",
        "message": "ERROR payment-service timeout talking to downstream",
        "logStream": "api/i-sample/abc",
    },
    {
        "timestamp": "2026-10-30T18:01:14Z",
        "message": "WARN retrying GetItem after ProvisionedThroughputExceeded",
        "logStream": "api/i-sample/abc",
    },
]


class MockCloudWatchLogsAdapter:
    mode = "mock"

    async def describe_log_groups(self, prefix: str | None = None) -> list[dict[str, Any]]:
        logger.debug("Mock describe_log_groups prefix=%s", prefix)
        if not prefix:
            return list(MOCK_LOG_GROUPS)
        return [group for group in MOCK_LOG_GROUPS if group["logGroupName"].startswith(prefix)]

    async def start_insights_query(
        self,
        log_group_names: list[str],
        query_string: str,
        start_time: int,
        end_time: int,
    ) -> str:
        logger.debug(
            "Mock start_insights_query groups=%s query_chars=%s window=%s-%s",
            log_group_names,
            len(query_string),
            start_time,
            end_time,
        )
        return "mock-query-001"

    async def get_query_results(self, query_id: str) -> dict[str, Any]:
        logger.debug("Mock get_query_results query_id=%s", query_id)
        return {"queryId": query_id, "status": "Complete", "results": list(MOCK_QUERY_ROWS)}


class MockCloudWatchMetricsAdapter:
    mode = "mock"

    async def list_metrics(
        self,
        namespace: str | None = None,
        metric_name: str | None = None,
    ) -> list[dict[str, Any]]:
        logger.debug("Mock list_metrics namespace=%s metric=%s", namespace, metric_name)
        return [
            {
                "namespace": namespace or "AWS/ECS",
                "metricName": metric_name or "CPUUtilization",
                "dimensions": [{"Name": "ServiceName", "Value": "sample-api"}],
            }
        ]

    async def get_metric_data(self, metric_name: str, namespace: str) -> dict[str, Any]:
        logger.debug("Mock get_metric_data %s/%s", namespace, metric_name)
        return {
            "namespace": namespace,
            "metricName": metric_name,
            "values": [12.0, 18.5, 41.0, 87.2],
            "status": "Complete",
        }
