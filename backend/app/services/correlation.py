"""Correlate logs with CloudWatch Metrics. Join logic is not implemented yet."""

from __future__ import annotations

from typing import Any

from app.adapters.aws.base import CloudWatchMetricsPort
from app.adapters.aws.factory import get_metrics_adapter
from app.core.logging import get_logger

logger = get_logger(__name__)


class CorrelationService:
    def __init__(self, metrics: CloudWatchMetricsPort | None = None) -> None:
        self._metrics = metrics or get_metrics_adapter()

    async def correlate(
        self,
        log_events: list[dict[str, Any]],
        namespace: str,
        metric_name: str,
    ) -> dict[str, Any]:
        logger.info(
            "Correlation called mode=%s events=%s metric=%s/%s (skeleton)",
            self._metrics.mode,
            len(log_events),
            namespace,
            metric_name,
        )
        metric = await self._metrics.get_metric_data(metric_name, namespace)
        return {
            "status": "skeleton",
            "event_count": len(log_events),
            "metric": metric,
            "links": [],
        }
