"""Ports for CloudWatch Logs and Metrics. Live callers stay behind these protocols."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


class AdapterNotImplementedError(NotImplementedError):
    """Raised when a live AWS operation is not wired yet."""


class AWSThrottlingError(Exception):
    """Raised when AWS returns a throttling error."""

    def __init__(self, message: str, retry_after_seconds: float | None = None):
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


class AWSCredentialsError(Exception):
    """Raised when AWS credentials are invalid or expired."""


class AWSAccessDeniedError(Exception):
    """Raised when access is denied to an AWS resource."""

    def __init__(self, message: str, resource: str | None = None):
        super().__init__(message)
        self.resource = resource


class AWSResourceNotFoundError(Exception):
    """Raised when an AWS resource is not found."""


class QueryTimeoutError(Exception):
    """Raised when a query exceeds its timeout."""


class QueryConcurrencyError(Exception):
    """Raised when too many concurrent queries are running."""


class ScanBudgetExceededError(Exception):
    """Raised when the scan budget limit is exceeded."""


@runtime_checkable
class CloudWatchLogsPort(Protocol):
    """Port for CloudWatch Logs operations."""

    mode: str
    account_alias: str | None
    region: str | None

    async def describe_log_groups(
        self,
        prefix: str | None = None,
        next_token: str | None = None,
        limit: int = 50,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Return log group summaries and pagination token."""
        ...

    async def list_tags_for_log_group(self, log_group_name: str) -> dict[str, str]:
        """Return tags for a log group."""
        ...

    async def start_insights_query(
        self,
        log_group_names: list[str],
        query_string: str,
        start_time: int,
        end_time: int,
        limit: int = 1000,
    ) -> str:
        """Start a Logs Insights query. Returns query ID."""
        ...

    async def get_query_results(self, query_id: str) -> dict[str, Any]:
        """Fetch Insights results with status and statistics."""
        ...

    async def stop_query(self, query_id: str) -> bool:
        """Stop a running query. Returns True if stopped."""
        ...

    async def describe_queries(
        self,
        log_group_name: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        """List queries with optional filters."""
        ...


@runtime_checkable
class CloudWatchMetricsPort(Protocol):
    """Port for CloudWatch Metrics operations."""

    mode: str

    async def list_metrics(
        self,
        namespace: str | None = None,
        metric_name: str | None = None,
    ) -> list[dict[str, Any]]: ...

    async def get_metric_data(self, metric_name: str, namespace: str) -> dict[str, Any]: ...
