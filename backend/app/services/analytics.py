"""Log analytics orchestration. Clustering and burst detection are not implemented."""

from __future__ import annotations

from typing import Any

from app.core.logging import get_logger

logger = get_logger(__name__)


class AnalyticsService:
    async def summarize(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        logger.info("Analytics summarize called event_count=%s (skeleton)", len(events))
        return {
            "status": "skeleton",
            "event_count": len(events),
            "clusters": [],
        }
