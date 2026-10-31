"""Live CloudWatch Logs adapter. Read-only investigation calls are not wired yet."""

from __future__ import annotations

from typing import Any

from app.adapters.aws.base import AdapterNotImplementedError


class BotoCloudWatchLogsAdapter:
    """Boundary for Logs Insights. Client construction is deferred to a later milestone."""

    mode = "live"

    async def describe_log_groups(self, prefix: str | None = None) -> list[dict[str, Any]]:
        raise AdapterNotImplementedError(
            "Live CloudWatch Logs Insights is not implemented in this milestone "
            f"(prefix={prefix!r}). Use AWS_USE_MOCK=true for local development."
        )

    async def start_insights_query(
        self,
        log_group_names: list[str],
        query_string: str,
        start_time: int,
        end_time: int,
    ) -> str:
        raise AdapterNotImplementedError(
            "Live StartQuery is not implemented in this milestone "
            f"(groups={len(log_group_names)}, query_chars={len(query_string)}, "
            f"window={start_time}-{end_time})."
        )

    async def get_query_results(self, query_id: str) -> dict[str, Any]:
        raise AdapterNotImplementedError(
            f"Live GetQueryResults is not implemented in this milestone (query_id={query_id!r})."
        )
