"""Log analytics orchestration using the Log Intelligence Engine."""

from __future__ import annotations

from typing import Any

from app.core.logging import get_logger
from app.intelligence.engine import LogIntelligenceEngine
from app.schemas.intelligence import IntelligenceSummary

logger = get_logger(__name__)


class AnalyticsService:
    """Service for analyzing log events using the Log Intelligence Engine."""

    def __init__(self, redact_pii: bool = True):
        """Initialize the analytics service.

        Args:
            redact_pii: Whether to redact PII from log messages
        """
        self._engine = LogIntelligenceEngine(redact_pii=redact_pii)

    async def summarize(
        self,
        events: list[dict[str, Any]],
        baseline_events: list[dict[str, Any]] | None = None,
        include_samples: bool = True,
        max_samples: int = 5,
        top_failures_count: int = 10,
    ) -> IntelligenceSummary:
        """Analyze and summarize log events.

        Args:
            events: List of log events to analyze
            baseline_events: Optional baseline events for comparison
            include_samples: Include sample events in clusters
            max_samples: Maximum samples per cluster
            top_failures_count: Number of top failures to return

        Returns:
            Intelligence summary with clusters, groups, and metrics
        """
        logger.info(
            "Analytics summarize called event_count=%s baseline_count=%s",
            len(events),
            len(baseline_events) if baseline_events else 0,
        )

        summary = self._engine.analyze_events(
            events=events,
            baseline_events=baseline_events,
            include_samples=include_samples,
            max_samples=max_samples,
            top_failures_count=top_failures_count,
        )

        logger.info(
            "Analytics summary generated summary_id=%s unique_events=%s clusters=%s",
            summary.summary_id,
            summary.total_events_after_dedup,
            len(summary.failure_clusters),
        )

        return summary

    async def classify_single(
        self,
        message: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Classify a single log message.

        Args:
            message: The log message to classify
            **kwargs: Additional parameters (timestamp, log_group, etc.)

        Returns:
            Classification result as dict
        """
        event = self._engine.classify_event(message=message, **kwargs)
        return event.model_dump()
