"""Ports for CloudWatch Logs and Metrics. Live callers stay behind these protocols."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


class AdapterNotImplementedError(NotImplementedError):
    """Raised when a live AWS operation is not wired yet."""


@runtime_checkable
class CloudWatchLogsPort(Protocol):
    mode: str

    async def describe_log_groups(self, prefix: str | None = None) -> list[dict[str, Any]]:
        """Return log group summaries. Mocked locally; live query engine is later."""
        ...

    async def start_insights_query(
        self,
        log_group_names: list[str],
        query_string: str,
        start_time: int,
        end_time: int,
    ) -> str:
        """Start a Logs Insights query. Foundation returns mock ids only."""
        ...

    async def get_query_results(self, query_id: str) -> dict[str, Any]:
        """Fetch Insights results. Foundation returns canned rows in mock mode."""
        ...


@runtime_checkable
class CloudWatchMetricsPort(Protocol):
    mode: str

    async def list_metrics(
        self,
        namespace: str | None = None,
        metric_name: str | None = None,
    ) -> list[dict[str, Any]]: ...

    async def get_metric_data(self, metric_name: str, namespace: str) -> dict[str, Any]: ...
