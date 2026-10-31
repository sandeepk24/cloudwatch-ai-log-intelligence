"""Live CloudWatch Metrics adapter. Read-only investigation calls are not wired yet."""

from __future__ import annotations

from typing import Any

from app.adapters.aws.base import AdapterNotImplementedError


class BotoCloudWatchMetricsAdapter:
    """Boundary for CloudWatch Metrics. Client construction is deferred to a later milestone."""

    mode = "live"

    async def list_metrics(
        self,
        namespace: str | None = None,
        metric_name: str | None = None,
    ) -> list[dict[str, Any]]:
        raise AdapterNotImplementedError(
            "Live ListMetrics is not implemented in this milestone "
            f"(namespace={namespace!r}, metric_name={metric_name!r})."
        )

    async def get_metric_data(self, metric_name: str, namespace: str) -> dict[str, Any]:
        raise AdapterNotImplementedError(
            "Live GetMetricData is not implemented in this milestone "
            f"(namespace={namespace!r}, metric_name={metric_name!r})."
        )
