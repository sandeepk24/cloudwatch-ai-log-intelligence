"""Orchestrates CloudWatch anomaly and pattern analysis.

This service fetches classified log events (and, where available, metric
datapoints), then delegates to the deterministic, independently unit-tested
functions in `app.analytics.*` to build the responses served by
`/api/analytics/patterns`, `/api/analytics/anomalies`, and
`/api/analytics/trends`.

Native CloudWatch support
-------------------------
When ``prefer_native=True`` is requested for pattern analysis, this service
attempts CloudWatch Logs Insights' `pattern` query command via the
underlying adapter and parses its clustered output (`@pattern`,
`@sampleCount`, `@severityLabel`) into the same `LogPattern` shape used by
the local implementation. If that command is unavailable, unpermitted, or
the adapter doesn't support it (`AWSFeatureNotSupportedError` /
`AdapterNotImplementedError` / any other failure), this service
transparently falls back to the local statistical implementation so the
endpoint still returns a useful result -- callers can tell which path was
used via ``data_source`` in the response.

Mock mode intentionally reports its synthetic pattern rows as unavailable
for native sourcing (see `_fetch_native_patterns`): they exist to exercise
the adapter contract, not to be mistaken for real CloudWatch clustering.

Native pattern diffing requires *both* windows to come from the native
command, since native clustering text is not guaranteed to be comparable to
locally-normalized pattern text. If the baseline window can't also be
fetched natively, the diff is skipped with an explicit note rather than
silently mixing two incompatible pattern sources.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from app.adapters.aws.base import AdapterNotImplementedError, AWSFeatureNotSupportedError
from app.adapters.aws.factory import get_metrics_adapter
from app.analytics.baseline import bucketize, partition_into_periods
from app.analytics.patterns import coerce_severity, diff_patterns, extract_patterns, pattern_hash
from app.analytics.resource_signals import analyze_resource_signal
from app.analytics.trends import (
    build_trend_points,
    compare_to_baseline_error_rate,
    detect_error_rate_anomalies,
    detect_frequency_spikes,
    find_recurring_warnings,
)
from app.core.config import settings
from app.core.logging import get_logger
from app.intelligence.engine import LogIntelligenceEngine
from app.schemas.analytics import (
    AnalysisStatus,
    AnomaliesResponse,
    AnomalyThresholds,
    DataSource,
    LogPattern,
    PatternsResponse,
    TrendsResponse,
)
from app.schemas.logs import StartQueryRequest, TimeRange, TimeRangePreset
from app.services.ingestion import LogIngestionService

logger = get_logger(__name__)

DEFAULT_QUERY_STRING = (
    "fields @timestamp, @message, @logStream, @ptr | sort @timestamp asc | limit 10000"
)

_PRESET_DELTAS: dict[TimeRangePreset, timedelta] = {
    TimeRangePreset.LAST_15_MINUTES: timedelta(minutes=15),
    TimeRangePreset.LAST_1_HOUR: timedelta(hours=1),
    TimeRangePreset.LAST_6_HOURS: timedelta(hours=6),
    TimeRangePreset.LAST_24_HOURS: timedelta(hours=24),
}


def _resolve_window(
    preset: TimeRangePreset,
    start_time: datetime | None,
    end_time: datetime | None,
) -> tuple[datetime, datetime]:
    if start_time and end_time:
        return start_time, end_time
    now = datetime.now(UTC)
    delta = _PRESET_DELTAS.get(preset, timedelta(hours=1))
    return now - delta, now


class PatternAnalysisService:
    """Fetches and analyzes log events for pattern, anomaly, and trend
    detection across one or more CloudWatch log groups."""

    def __init__(
        self,
        ingestion: LogIngestionService | None = None,
        intelligence: LogIntelligenceEngine | None = None,
    ):
        self._ingestion = ingestion or LogIngestionService()
        self._intelligence = intelligence or LogIntelligenceEngine(redact_pii=True)

    # -------------------------------------------------------------------
    # Data fetching
    # -------------------------------------------------------------------

    async def fetch_classified_events(
        self,
        log_group_names: list[str],
        start_time: datetime,
        end_time: datetime,
        account_alias: str | None = None,
        query_string: str = DEFAULT_QUERY_STRING,
    ) -> list[dict[str, Any]]:
        """Fetch events for a window via CloudWatch Logs Insights and run
        them through the Log Intelligence Engine to attach severity /
        redaction, returning plain dicts ready for `app.analytics.*`.
        """
        request = StartQueryRequest(
            log_group_names=log_group_names,
            query_string=query_string,
            time_range=TimeRange(
                preset=TimeRangePreset.CUSTOM,
                start_time=start_time,
                end_time=end_time,
            ),
            account_alias=account_alias,
        )
        started = await self._ingestion.start_query(request)
        result = await self._ingestion.poll_query_until_complete(
            started.query_id, account_alias=account_alias
        )

        events: list[dict[str, Any]] = []
        for log_event in result.events:
            classified = self._intelligence.classify_event(
                message=log_event.message,
                timestamp=log_event.timestamp,
                log_group=log_event.log_group,
                log_stream=log_event.log_stream,
                raw_fields=log_event.raw_fields,
                ptr=log_event.ptr,
            )
            events.append(
                {
                    "message": classified.redacted_message,
                    "timestamp": classified.timestamp,
                    "severity": classified.severity.value,
                    "log_group": classified.log_group,
                    "ptr": classified.ptr,
                }
            )
        return events

    # -------------------------------------------------------------------
    # GET /api/analytics/patterns
    # -------------------------------------------------------------------

    async def get_patterns(
        self,
        log_group_names: list[str],
        time_range_preset: TimeRangePreset = TimeRangePreset.LAST_1_HOUR,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        baseline_periods: int = 1,
        account_alias: str | None = None,
        min_occurrences: int = 1,
        prefer_native: bool = False,
    ) -> PatternsResponse:
        window_start, window_end = _resolve_window(time_range_preset, start_time, end_time)
        duration = window_end - window_start
        notes: list[str] = []
        status = AnalysisStatus.OK

        native_current: list[LogPattern] | None = None
        if prefer_native:
            native_current = await self._fetch_native_patterns(
                log_group_names, window_start, window_end, account_alias
            )
            if native_current is None:
                notes.append(
                    "prefer_native=true but native CloudWatch Logs Insights `pattern` "
                    "results were unavailable (unsupported, unpermitted, or running in "
                    "mock mode); used local statistical pattern clustering instead."
                )

        if native_current is not None:
            data_source = DataSource.CLOUDWATCH_NATIVE
            current_patterns = native_current
            total_events = sum(p.occurrence_count for p in current_patterns)
        else:
            data_source = DataSource.LOCAL_STATISTICAL
            current_events = await self.fetch_classified_events(
                log_group_names, window_start, window_end, account_alias
            )
            current_patterns = extract_patterns(current_events, min_occurrences=min_occurrences)
            total_events = len(current_events)

        diff = None
        if baseline_periods <= 0:
            notes.append(
                "baseline_periods=0: newly-appearing pattern detection was skipped "
                "(no baseline window requested)."
            )
            status = AnalysisStatus.PARTIAL
        else:
            baseline_start = window_start - (duration * baseline_periods)

            if data_source == DataSource.CLOUDWATCH_NATIVE:
                native_baseline = await self._fetch_native_patterns(
                    log_group_names, baseline_start, window_start, account_alias
                )
                if native_baseline is None:
                    notes.append(
                        "Native pattern diffing requires both windows to use the native "
                        "`pattern` command; the baseline window could not be fetched "
                        "natively, so the diff was skipped."
                    )
                    status = AnalysisStatus.PARTIAL
                else:
                    diff = diff_patterns(current_patterns, native_baseline)
            else:
                baseline_events = await self.fetch_classified_events(
                    log_group_names, baseline_start, window_start, account_alias
                )
                if not baseline_events:
                    notes.append(
                        "Baseline window contained no events; cannot reliably distinguish "
                        "'new' patterns from patterns that simply weren't sampled before. "
                        "Current patterns are reported without baseline comparison."
                    )
                    status = AnalysisStatus.INSUFFICIENT_DATA
                else:
                    baseline_patterns = extract_patterns(baseline_events, min_occurrences=min_occurrences)
                    diff = diff_patterns(current_patterns, baseline_patterns)

        return PatternsResponse(
            status=status,
            data_source=data_source,
            time_range_start=window_start,
            time_range_end=window_end,
            total_events=total_events,
            patterns=current_patterns,
            diff=diff,
            notes=notes,
        )

    async def _fetch_native_patterns(
        self,
        log_group_names: list[str],
        start: datetime,
        end: datetime,
        account_alias: str | None,
    ) -> list[LogPattern] | None:
        """Attempt native CloudWatch Logs Insights pattern clustering.
        Returns None (never raises) when unavailable, so callers can fall
        back to local computation."""
        adapter = self._ingestion._get_adapter(account_alias=account_alias)

        if not hasattr(adapter, "start_pattern_query"):
            return None
        if getattr(adapter, "mode", "") == "mock":
            # Mock mode's pattern rows are a synthetic approximation for
            # exercising the adapter contract, not real clustering; never
            # report them as "cloudwatch_native" to API consumers.
            return None

        try:
            query_id = await adapter.start_pattern_query(
                log_group_names=log_group_names,
                start_time=int(start.timestamp()),
                end_time=int(end.timestamp()),
            )
            result = await self._poll_raw_query(adapter, query_id)
        except (AWSFeatureNotSupportedError, AdapterNotImplementedError) as e:
            logger.info("Native pattern query unavailable: %s", e)
            return None
        except Exception as e:
            logger.warning("Native pattern query failed, falling back to local: %s", e)
            return None

        if result.get("status") != "Complete":
            return None

        return self._parse_native_pattern_rows(result.get("results", []), start, end)

    async def _poll_raw_query(
        self,
        adapter: Any,
        query_id: str,
        timeout_seconds: int | None = None,
    ) -> dict[str, Any]:
        """Minimal poll loop operating directly on an adapter's raw
        get_query_results, used for query shapes (like `pattern`) that
        LogIngestionService's LogEvent-oriented parsing doesn't understand.
        """
        timeout = timeout_seconds or settings.cw_query_timeout_seconds
        poll_interval = settings.cw_query_poll_interval_ms / 1000.0
        started_at = time.time()

        while True:
            result = await adapter.get_query_results(query_id)
            if result.get("status") in {"Complete", "Failed", "Cancelled"}:
                return result
            if time.time() - started_at >= timeout:
                with contextlib.suppress(Exception):
                    await adapter.stop_query(query_id)
                return result
            await asyncio.sleep(poll_interval)

    def _parse_native_pattern_rows(
        self,
        rows: list[list[dict[str, str]]],
        window_start: datetime,
        window_end: datetime,
    ) -> list[LogPattern]:
        """Parse CloudWatch Logs Insights `pattern` command output rows into
        LogPattern records.

        The `pattern` command does not return per-pattern first/last-seen
        timestamps in its result fields, so those are approximated as the
        query window boundaries -- this is a known limitation of the native
        path, noted in the response.
        """
        parsed: list[tuple[str, int, str, str]] = []
        total = 0
        for row in rows:
            fields = {item["field"]: item["value"] for item in row}
            pattern_text = fields.get("@pattern", "")
            try:
                sample_count = int(float(fields.get("@sampleCount", "0") or 0))
            except ValueError:
                sample_count = 0
            severity_label = fields.get("@severityLabel", "INFO").upper()
            sample_message = fields.get("@logSamples", pattern_text)
            total += sample_count
            parsed.append((pattern_text, sample_count, severity_label, sample_message))

        if total == 0:
            return []

        patterns: list[LogPattern] = []
        for pattern_text, sample_count, severity_label, sample_message in parsed:
            severity = coerce_severity(severity_label)
            patterns.append(
                LogPattern(
                    pattern_id=pattern_hash(severity_label, pattern_text),
                    normalized_pattern=pattern_text,
                    severity=severity,
                    occurrence_count=sample_count,
                    ratio=sample_count / total,
                    first_seen=window_start,
                    last_seen=window_end,
                    representative_message=sample_message,
                )
            )

        patterns.sort(key=lambda p: p.occurrence_count, reverse=True)
        return patterns

    # -------------------------------------------------------------------
    # GET /api/analytics/anomalies
    # -------------------------------------------------------------------

    async def get_anomalies(
        self,
        log_group_names: list[str],
        time_range_preset: TimeRangePreset = TimeRangePreset.LAST_1_HOUR,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        bucket_minutes: int = 5,
        history_periods: int = 6,
        thresholds: AnomalyThresholds | None = None,
        metric_namespace: str | None = None,
        metric_name: str | None = None,
        account_alias: str | None = None,
        recurring_min_periods: int = 2,
    ) -> AnomaliesResponse:
        thresholds = thresholds or AnomalyThresholds()
        window_start, window_end = _resolve_window(time_range_preset, start_time, end_time)
        duration = window_end - window_start

        history_start = window_start - (duration * history_periods)
        all_events = await self.fetch_classified_events(
            log_group_names, history_start, window_end, account_alias
        )

        all_buckets = bucketize(all_events, history_start, window_end, bucket_minutes)
        current_buckets = [b for b in all_buckets if b.start >= window_start]

        notes: list[str] = []
        status = AnalysisStatus.OK

        buckets_available_as_history = len(all_buckets) - len(current_buckets)
        if history_periods <= 0 or buckets_available_as_history < thresholds.min_history_points:
            notes.append(
                f"Only {buckets_available_as_history} historical bucket(s) available before the "
                f"current window; {thresholds.min_history_points} required. Frequency/error-rate "
                "anomaly detection was skipped for buckets lacking sufficient history."
            )
            status = AnalysisStatus.INSUFFICIENT_DATA

        frequency_results = detect_frequency_spikes(all_buckets, thresholds)
        error_rate_results = detect_error_rate_anomalies(all_buckets, thresholds)

        # Only surface results within the requested current window; earlier
        # buckets exist purely to build the rolling baseline.
        frequency_anomalies = [r for r in frequency_results if r.bucket_start >= window_start]
        error_rate_anomalies = [r for r in error_rate_results if r.bucket_start >= window_start]

        # Recurring warnings, tracked over the same historical periods.
        period_minutes = max(1, int(duration.total_seconds() // 60) or 1)
        periods = partition_into_periods(all_events, history_start, window_end, period_minutes)
        if len(periods) < 2:
            notes.append(
                "Fewer than 2 historical periods available; recurring-warning "
                "frequency could not be established."
            )
        recurring_warnings = find_recurring_warnings(periods, min_periods_seen=recurring_min_periods)

        resource_signals = []
        if metric_namespace and metric_name:
            metrics_adapter = get_metrics_adapter()
            signal = await analyze_resource_signal(
                metrics_adapter, metric_namespace, metric_name, thresholds
            )
            resource_signals.append(signal)
            if signal.status != AnalysisStatus.OK and status == AnalysisStatus.OK:
                status = AnalysisStatus.PARTIAL

        incident_count = sum(
            1 for r in (*frequency_anomalies, *error_rate_anomalies) if r.is_incident
        )

        return AnomaliesResponse(
            status=status,
            data_source=DataSource.LOCAL_STATISTICAL,
            time_range_start=window_start,
            time_range_end=window_end,
            thresholds=thresholds,
            frequency_anomalies=frequency_anomalies,
            error_rate_anomalies=error_rate_anomalies,
            recurring_warnings=recurring_warnings,
            resource_signals=resource_signals,
            incident_count=incident_count,
            notes=notes,
        )

    # -------------------------------------------------------------------
    # GET /api/analytics/trends
    # -------------------------------------------------------------------

    async def get_trends(
        self,
        log_group_names: list[str],
        time_range_preset: TimeRangePreset = TimeRangePreset.LAST_24_HOURS,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        bucket_minutes: int = 15,
        history_periods: int = 3,
        thresholds: AnomalyThresholds | None = None,
        recurring_min_periods: int = 2,
        account_alias: str | None = None,
    ) -> TrendsResponse:
        thresholds = thresholds or AnomalyThresholds()
        window_start, window_end = _resolve_window(time_range_preset, start_time, end_time)
        duration = window_end - window_start

        history_start = (
            window_start - (duration * history_periods) if history_periods > 0 else window_start
        )
        all_events = await self.fetch_classified_events(
            log_group_names, history_start, window_end, account_alias
        )

        all_buckets = bucketize(all_events, history_start, window_end, bucket_minutes)
        current_buckets = [b for b in all_buckets if b.start >= window_start]
        baseline_buckets = [b for b in all_buckets if b.end <= window_start]

        points = build_trend_points(current_buckets)

        notes: list[str] = []
        status = AnalysisStatus.OK

        current_epm, baseline_epm, pct_change = compare_to_baseline_error_rate(
            current_buckets, baseline_buckets
        )
        if baseline_epm is None:
            notes.append(
                "No historical baseline window was available; "
                "change_from_baseline_pct could not be computed."
            )
            status = AnalysisStatus.INSUFFICIENT_DATA

        spike_results = detect_frequency_spikes(all_buckets, thresholds)
        spikes = [s for s in spike_results if s.bucket_start >= window_start]
        buckets_available_as_history = len(all_buckets) - len(current_buckets)
        if buckets_available_as_history < thresholds.min_history_points:
            notes.append(
                f"Only {buckets_available_as_history} historical bucket(s) available; "
                f"{thresholds.min_history_points} required for spike detection on the "
                "earliest buckets in the current window."
            )
            if status == AnalysisStatus.OK:
                status = AnalysisStatus.PARTIAL

        period_minutes = max(1, int(duration.total_seconds() // 60) or 1)
        periods = partition_into_periods(all_events, history_start, window_end, period_minutes)
        recurring_warnings = find_recurring_warnings(periods, min_periods_seen=recurring_min_periods)

        return TrendsResponse(
            status=status,
            time_range_start=window_start,
            time_range_end=window_end,
            bucket_minutes=bucket_minutes,
            points=points,
            baseline_error_rate_per_minute=baseline_epm,
            current_error_rate_per_minute=current_epm,
            change_from_baseline_pct=pct_change,
            spikes=spikes,
            recurring_warnings=recurring_warnings,
            notes=notes,
        )
