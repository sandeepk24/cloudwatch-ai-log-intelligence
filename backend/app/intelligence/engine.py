"""Log Intelligence Engine - main analysis orchestrator.

This module coordinates classification, pattern detection, fingerprinting,
deduplication, and summarization of log events.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from app.core.logging import get_logger
from app.schemas.intelligence import (
    ClassifiedEvent,
    ErrorRateMetrics,
    ExceptionGroup,
    FailureCluster,
    IntelligenceSummary,
    LogSeverity,
    PatternCategory,
    SeverityDistribution,
    TopFailure,
)

from .classifiers import LogClassifier
from .fingerprint import EventDeduplicator, compute_fingerprint, extract_exception_type
from .redaction import redact_for_ai
from .rules import DetectionRule

logger = get_logger(__name__)


class LogIntelligenceEngine:
    """Main engine for log analysis and intelligence extraction."""

    def __init__(
        self,
        severity_rules: list[DetectionRule] | None = None,
        pattern_rules: list[DetectionRule] | None = None,
        context_rules: list[DetectionRule] | None = None,
        redact_pii: bool = True,
    ):
        """Initialize the engine.

        Args:
            severity_rules: Custom severity detection rules
            pattern_rules: Custom pattern detection rules
            context_rules: Custom context extraction rules
            redact_pii: Whether to redact PII from messages
        """
        self._classifier = LogClassifier(severity_rules, pattern_rules, context_rules)
        self._redact_pii = redact_pii

    def classify_event(
        self,
        message: str,
        timestamp: datetime | None = None,
        log_group: str = "",
        log_stream: str | None = None,
        raw_fields: dict[str, Any] | None = None,
        ptr: str | None = None,
    ) -> ClassifiedEvent:
        """Classify a single log event.

        Args:
            message: The log message
            timestamp: Event timestamp
            log_group: Source log group
            log_stream: Source log stream
            raw_fields: Structured fields from the log
            ptr: Pointer to original evidence

        Returns:
            Classified event with patterns and context
        """
        timestamp = timestamp or datetime.now(UTC)

        # Classify the message
        severity, patterns, context = self._classifier.classify(
            message=message,
            timestamp=timestamp,
            log_group=log_group,
            log_stream=log_stream,
            raw_fields=raw_fields,
        )

        # Redact sensitive data
        redacted_message = redact_for_ai(message) if self._redact_pii else message

        # Get primary pattern category for fingerprinting
        primary_category = PatternCategory.UNKNOWN
        for pattern in patterns:
            if not pattern.is_false_positive:
                primary_category = pattern.category
                break

        # Compute fingerprint
        fp_result = compute_fingerprint(
            message=message,
            severity=severity,
            category=primary_category,
            log_group=log_group,
        )

        return ClassifiedEvent(
            original_message=message,
            redacted_message=redacted_message,
            severity=severity,
            patterns=patterns,
            context=context,
            fingerprint=fp_result.fingerprint,
            timestamp=timestamp,
            log_group=log_group,
            log_stream=log_stream,
            ptr=ptr,
        )

    def analyze_events(
        self,
        events: list[dict[str, Any]],
        baseline_events: list[dict[str, Any]] | None = None,
        include_samples: bool = True,
        max_samples: int = 5,
        top_failures_count: int = 10,
    ) -> IntelligenceSummary:
        """Analyze a batch of log events.

        Args:
            events: List of log events (dicts with message, timestamp, etc.)
            baseline_events: Optional baseline events for comparison
            include_samples: Include sample events in clusters
            max_samples: Maximum samples per cluster
            top_failures_count: Number of top failures to return

        Returns:
            Intelligence summary with clusters, groups, and metrics
        """
        summary_id = str(uuid.uuid4())[:8]
        now = datetime.now(UTC)

        # Classify all events
        classified_events: list[ClassifiedEvent] = []
        deduplicator = EventDeduplicator()

        for event_data in events:
            event = self._parse_and_classify_event(event_data)
            classified_events.append(event)
            deduplicator.add_event(event, max_samples=max_samples)

        if not classified_events:
            return self._empty_summary(summary_id, now)

        # Calculate time range
        timestamps = [e.timestamp for e in classified_events]
        time_start = min(timestamps)
        time_end = max(timestamps)

        # Calculate severity distribution
        severity_dist = self._calculate_severity_distribution(classified_events)

        # Build failure clusters
        failure_clusters = self._build_failure_clusters(
            classified_events, deduplicator, include_samples, max_samples
        )

        # Build exception groups
        exception_groups = self._build_exception_groups(
            classified_events, deduplicator, include_samples, max_samples
        )

        # Calculate error rate
        error_rate = self._calculate_error_rate(
            classified_events, baseline_events, time_start, time_end
        )

        # Get top failures
        top_failures = self._rank_top_failures(
            failure_clusters, top_failures_count
        )

        # Extract unique services and versions
        detected_services = self._extract_unique_services(classified_events)
        detected_versions = self._extract_unique_versions(classified_events)

        # Get dedup stats
        dedup_stats = deduplicator.get_stats()

        return IntelligenceSummary(
            summary_id=summary_id,
            generated_at=now,
            time_range_start=time_start,
            time_range_end=time_end,
            total_events_analyzed=len(events),
            total_events_after_dedup=dedup_stats["unique_events"],
            deduplication_ratio=dedup_stats["deduplication_ratio"],
            severity_distribution=severity_dist,
            error_rate=error_rate,
            top_failures=top_failures,
            exception_groups=exception_groups,
            failure_clusters=failure_clusters,
            detected_services=detected_services,
            detected_versions=detected_versions,
            redaction_applied=self._redact_pii,
        )

    def _parse_and_classify_event(self, event_data: dict[str, Any]) -> ClassifiedEvent:
        """Parse an event dict and classify it."""
        message = event_data.get("message", event_data.get("@message", ""))

        # Handle timestamp
        ts = event_data.get("timestamp", event_data.get("@timestamp"))
        if isinstance(ts, datetime):
            timestamp = ts
        elif isinstance(ts, (int, float)):
            # Assume milliseconds if > 10 billion
            if ts > 1e10:
                ts = ts / 1000
            timestamp = datetime.fromtimestamp(ts, tz=UTC)
        elif isinstance(ts, str):
            try:
                timestamp = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                timestamp = datetime.now(UTC)
        else:
            timestamp = datetime.now(UTC)

        log_group = event_data.get("log_group", event_data.get("@log_group", ""))
        log_stream = event_data.get("log_stream", event_data.get("@log_stream"))
        ptr = event_data.get("ptr", event_data.get("@ptr"))

        # Get raw fields (everything except known fields)
        known_fields = {
            "message", "@message", "timestamp", "@timestamp",
            "log_group", "@log_group", "log_stream", "@log_stream",
            "ptr", "@ptr"
        }
        raw_fields = {k: v for k, v in event_data.items() if k not in known_fields}

        return self.classify_event(
            message=message,
            timestamp=timestamp,
            log_group=log_group,
            log_stream=log_stream,
            raw_fields=raw_fields if raw_fields else None,
            ptr=ptr,
        )

    def _empty_summary(self, summary_id: str, now: datetime) -> IntelligenceSummary:
        """Create an empty summary when no events are provided."""
        return IntelligenceSummary(
            summary_id=summary_id,
            generated_at=now,
            time_range_start=now,
            time_range_end=now,
            total_events_analyzed=0,
            total_events_after_dedup=0,
            deduplication_ratio=0.0,
            severity_distribution=SeverityDistribution(),
            error_rate=ErrorRateMetrics(
                errors_per_minute=0,
                errors_per_hour=0,
                time_window_minutes=0,
            ),
            redaction_applied=self._redact_pii,
        )

    def _calculate_severity_distribution(
        self, events: list[ClassifiedEvent]
    ) -> SeverityDistribution:
        """Calculate severity distribution from events."""
        counts = defaultdict(int)
        for event in events:
            counts[event.severity] += 1

        return SeverityDistribution(
            error_count=counts[LogSeverity.ERROR],
            warn_count=counts[LogSeverity.WARN],
            info_count=counts[LogSeverity.INFO],
            debug_count=counts[LogSeverity.DEBUG] + counts[LogSeverity.TRACE],
            unknown_count=counts[LogSeverity.UNKNOWN],
            total_count=len(events),
        )

    def _build_failure_clusters(
        self,
        events: list[ClassifiedEvent],
        deduplicator: EventDeduplicator,
        include_samples: bool,
        max_samples: int,
    ) -> list[FailureCluster]:
        """Build failure clusters from events."""
        clusters: list[FailureCluster] = []

        # Group by fingerprint
        fingerprint_events: dict[str, list[ClassifiedEvent]] = defaultdict(list)
        for event in events:
            # Only cluster errors and warnings
            if event.severity not in (LogSeverity.ERROR, LogSeverity.WARN):
                continue
            # Skip false positives
            has_real_pattern = any(
                p for p in event.patterns if not p.is_false_positive
            )
            if event.patterns and not has_real_pattern:
                continue
            fingerprint_events[event.fingerprint].append(event)

        for fingerprint, fp_events in fingerprint_events.items():
            if not fp_events:
                continue

            representative = fp_events[0]
            first_seen = min(e.timestamp for e in fp_events)
            last_seen = max(e.timestamp for e in fp_events)

            # Calculate events per minute
            duration_minutes = (last_seen - first_seen).total_seconds() / 60
            events_per_minute = (
                len(fp_events) / duration_minutes if duration_minutes > 0 else len(fp_events)
            )

            # Get primary category
            category = PatternCategory.UNKNOWN
            for pattern in representative.patterns:
                if not pattern.is_false_positive:
                    category = pattern.category
                    break

            # Get affected services and log groups
            affected_services = list({
                e.context.service_name
                for e in fp_events
                if e.context.service_name
            })
            affected_log_groups = list({e.log_group for e in fp_events if e.log_group})

            # Get evidence links
            evidence_links = [e.ptr for e in fp_events[:max_samples] if e.ptr]

            cluster = FailureCluster(
                cluster_id=f"cluster-{fingerprint[:8]}",
                fingerprint=fingerprint,
                category=category,
                severity=representative.severity,
                description=representative.redacted_message[:200],
                occurrence_count=len(fp_events),
                first_seen=first_seen,
                last_seen=last_seen,
                errors_per_minute=events_per_minute,
                representative_event=representative,
                sample_events=fp_events[:max_samples] if include_samples else [],
                affected_services=affected_services,
                affected_log_groups=affected_log_groups,
                evidence_links=evidence_links,
            )
            clusters.append(cluster)

        # Sort by occurrence count
        clusters.sort(key=lambda c: c.occurrence_count, reverse=True)

        return clusters

    def _build_exception_groups(
        self,
        events: list[ClassifiedEvent],
        deduplicator: EventDeduplicator,
        include_samples: bool,
        max_samples: int,
    ) -> list[ExceptionGroup]:
        """Build exception groups from events."""
        groups: list[ExceptionGroup] = []

        # Group by exception type
        exception_events: dict[str, list[ClassifiedEvent]] = defaultdict(list)
        for event in events:
            exception_type = extract_exception_type(event.original_message)
            if exception_type:
                exception_events[exception_type].append(event)

        for exception_type, ex_events in exception_events.items():
            if not ex_events:
                continue

            representative = ex_events[0]
            first_seen = min(e.timestamp for e in ex_events)
            last_seen = max(e.timestamp for e in ex_events)

            # Get affected services and log groups
            affected_services = list({
                e.context.service_name
                for e in ex_events
                if e.context.service_name
            })
            affected_log_groups = list({e.log_group for e in ex_events if e.log_group})

            # Create a simplified message pattern
            message_pattern = representative.redacted_message[:100]

            group = ExceptionGroup(
                group_id=f"ex-{representative.fingerprint[:8]}",
                exception_type=exception_type,
                message_pattern=message_pattern,
                fingerprint=representative.fingerprint,
                occurrence_count=len(ex_events),
                first_seen=first_seen,
                last_seen=last_seen,
                representative_event=representative,
                sample_events=ex_events[:max_samples] if include_samples else [],
                affected_services=affected_services,
                affected_log_groups=affected_log_groups,
            )
            groups.append(group)

        # Sort by occurrence count
        groups.sort(key=lambda g: g.occurrence_count, reverse=True)

        return groups

    def _calculate_error_rate(
        self,
        events: list[ClassifiedEvent],
        baseline_events: list[dict[str, Any]] | None,
        time_start: datetime,
        time_end: datetime,
    ) -> ErrorRateMetrics:
        """Calculate error rate metrics."""
        duration_minutes = max(1, (time_end - time_start).total_seconds() / 60)

        error_count = sum(1 for e in events if e.severity == LogSeverity.ERROR)
        errors_per_minute = error_count / duration_minutes
        errors_per_hour = errors_per_minute * 60

        baseline_epm = None
        baseline_eph = None
        change_percentage = None
        is_elevated = False

        if baseline_events:
            # Classify baseline events
            baseline_classified = [
                self._parse_and_classify_event(e) for e in baseline_events
            ]
            if baseline_classified:
                baseline_timestamps = [e.timestamp for e in baseline_classified]
                baseline_start = min(baseline_timestamps)
                baseline_end = max(baseline_timestamps)
                baseline_duration = max(
                    1, (baseline_end - baseline_start).total_seconds() / 60
                )

                baseline_error_count = sum(
                    1 for e in baseline_classified if e.severity == LogSeverity.ERROR
                )
                baseline_epm = baseline_error_count / baseline_duration
                baseline_eph = baseline_epm * 60

                if baseline_epm > 0:
                    change_percentage = (
                        (errors_per_minute - baseline_epm) / baseline_epm
                    ) * 100
                    # Consider elevated if > 50% increase
                    is_elevated = change_percentage > 50

        return ErrorRateMetrics(
            errors_per_minute=errors_per_minute,
            errors_per_hour=errors_per_hour,
            baseline_errors_per_minute=baseline_epm,
            baseline_errors_per_hour=baseline_eph,
            change_percentage=change_percentage,
            is_elevated=is_elevated,
            time_window_minutes=int(duration_minutes),
        )

    def _rank_top_failures(
        self,
        clusters: list[FailureCluster],
        top_n: int,
    ) -> list[TopFailure]:
        """Rank top failures by impact score."""
        top_failures: list[TopFailure] = []

        # Calculate impact scores
        max_count = max((c.occurrence_count for c in clusters), default=1)
        max_rate = max((c.errors_per_minute for c in clusters), default=1)

        for i, cluster in enumerate(clusters[:top_n]):
            # Impact score based on count and rate
            count_score = cluster.occurrence_count / max_count if max_count > 0 else 0
            rate_score = cluster.errors_per_minute / max_rate if max_rate > 0 else 0

            # Weight count more than rate
            impact_score = (count_score * 0.7) + (rate_score * 0.3)

            # Boost score for more severe categories
            severity_boost = {
                PatternCategory.OUT_OF_MEMORY: 0.2,
                PatternCategory.DATABASE_ERROR: 0.15,
                PatternCategory.HTTP_SERVER_ERROR: 0.1,
                PatternCategory.CONNECTION_TIMEOUT: 0.1,
            }
            impact_score += severity_boost.get(cluster.category, 0)
            impact_score = min(1.0, impact_score)

            top_failures.append(
                TopFailure(
                    rank=i + 1,
                    cluster=cluster,
                    impact_score=impact_score,
                )
            )

        # Re-sort by impact score
        top_failures.sort(key=lambda f: f.impact_score, reverse=True)
        for i, failure in enumerate(top_failures):
            failure.rank = i + 1

        return top_failures

    def _extract_unique_services(self, events: list[ClassifiedEvent]) -> list[str]:
        """Extract unique service names from events."""
        return sorted({
            e.context.service_name
            for e in events
            if e.context.service_name
        })

    def _extract_unique_versions(self, events: list[ClassifiedEvent]) -> list[str]:
        """Extract unique deployment versions from events."""
        return sorted({
            e.context.deployment_version
            for e in events
            if e.context.deployment_version
        })


# Module-level singleton
_engine: LogIntelligenceEngine | None = None


def get_intelligence_engine() -> LogIntelligenceEngine:
    """Get the default intelligence engine instance."""
    global _engine
    if _engine is None:
        _engine = LogIntelligenceEngine()
    return _engine


def analyze_events(
    events: list[dict[str, Any]],
    baseline_events: list[dict[str, Any]] | None = None,
    **kwargs,
) -> IntelligenceSummary:
    """Convenience function to analyze events using the default engine."""
    engine = get_intelligence_engine()
    return engine.analyze_events(events, baseline_events, **kwargs)
