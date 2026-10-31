"""CloudWatch log ingestion orchestration with query lifecycle management."""

from __future__ import annotations

import asyncio
import contextlib
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from app.adapters.aws.base import (
    AWSAccessDeniedError,
    AWSThrottlingError,
    CloudWatchLogsPort,
    QueryConcurrencyError,
    QueryTimeoutError,
    ScanBudgetExceededError,
)
from app.adapters.aws.factory import get_all_logs_adapters, get_logs_adapter
from app.core.config import settings
from app.core.logging import get_logger
from app.schemas.logs import (
    ActiveQueriesResponse,
    ActiveQuery,
    CancelQueryResponse,
    LogEvent,
    LogGroup,
    LogGroupFilter,
    LogGroupListResponse,
    QueryResultsResponse,
    QueryStatistics,
    QueryStatus,
    StartQueryRequest,
    StartQueryResponse,
    TimeRange,
    TimeRangePreset,
)

logger = get_logger(__name__)


def _time_range_to_epoch(time_range: TimeRange) -> tuple[int, int]:
    """Convert a TimeRange to Unix epoch timestamps in seconds."""
    now = datetime.now(UTC)

    if time_range.preset == TimeRangePreset.CUSTOM:
        if time_range.start_time is None or time_range.end_time is None:
            raise ValueError("Custom time range requires start_time and end_time")
        return (
            int(time_range.start_time.timestamp()),
            int(time_range.end_time.timestamp()),
        )

    delta_map = {
        TimeRangePreset.LAST_15_MINUTES: timedelta(minutes=15),
        TimeRangePreset.LAST_1_HOUR: timedelta(hours=1),
        TimeRangePreset.LAST_6_HOURS: timedelta(hours=6),
        TimeRangePreset.LAST_24_HOURS: timedelta(hours=24),
    }

    delta = delta_map.get(time_range.preset, timedelta(hours=1))
    start = now - delta
    return int(start.timestamp()), int(now.timestamp())


def _parse_insights_result(
    result: list[dict[str, str]],
    log_group: str,
    account_alias: str | None,
    region: str | None,
) -> LogEvent:
    """Parse a CloudWatch Logs Insights result row into a LogEvent."""
    fields = {item["field"]: item["value"] for item in result}

    # Parse timestamp
    ts_str = fields.get("@timestamp", "")
    try:
        timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        timestamp = datetime.now(UTC)

    # Parse ingestion time if present
    ingestion_time = None
    if "@ingestionTime" in fields:
        with contextlib.suppress(ValueError, AttributeError):
            ingestion_time = datetime.fromisoformat(fields["@ingestionTime"].replace("Z", "+00:00"))

    return LogEvent(
        timestamp=timestamp,
        message=fields.get("@message", ""),
        log_group=fields.get("@logGroup", log_group),
        log_stream=fields.get("@logStream"),
        ingestion_time=ingestion_time,
        ptr=fields.get("@ptr"),
        account_alias=account_alias,
        region=region,
        raw_fields={k: v for k, v in fields.items() if not k.startswith("@")},
    )


class QueryTracker:
    """Track active queries for concurrency control and timeout management."""

    def __init__(self):
        self._active: dict[str, dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    async def register(
        self,
        query_id: str,
        log_group_names: list[str],
        query_string: str,
        account_alias: str | None,
    ) -> None:
        """Register a new active query."""
        async with self._lock:
            if len(self._active) >= settings.cw_query_max_concurrency:
                raise QueryConcurrencyError(
                    f"Maximum concurrent queries ({settings.cw_query_max_concurrency}) reached"
                )
            self._active[query_id] = {
                "log_group_names": log_group_names,
                "query_string": query_string,
                "account_alias": account_alias,
                "started_at": datetime.now(UTC),
            }

    async def unregister(self, query_id: str) -> None:
        """Remove a query from tracking."""
        async with self._lock:
            self._active.pop(query_id, None)

    async def get_active(self) -> list[ActiveQuery]:
        """Get list of active queries."""
        async with self._lock:
            return [
                ActiveQuery(
                    query_id=qid,
                    log_group_names=info["log_group_names"],
                    query_string=info["query_string"],
                    status=QueryStatus.RUNNING,
                    started_at=info["started_at"],
                    account_alias=info["account_alias"],
                )
                for qid, info in self._active.items()
            ]

    async def count(self) -> int:
        """Get count of active queries."""
        async with self._lock:
            return len(self._active)


# Global query tracker
_query_tracker = QueryTracker()


class LogIngestionService:
    """Service for CloudWatch log group discovery and querying."""

    def __init__(self, logs: CloudWatchLogsPort | None = None):
        self._logs = logs
        self._total_bytes_scanned: float = 0

    def _get_adapter(self, account_alias: str | None = None) -> CloudWatchLogsPort:
        """Get the appropriate adapter for the account."""
        if self._logs is not None:
            return self._logs
        return get_logs_adapter(account_alias=account_alias)

    async def list_log_groups(
        self,
        filter_params: LogGroupFilter | None = None,
        next_token: str | None = None,
        limit: int = 50,
    ) -> LogGroupListResponse:
        """List and filter log groups across configured accounts.

        Args:
            filter_params: Optional filters for log groups
            next_token: Pagination token
            limit: Maximum number of results per page

        Returns:
            LogGroupListResponse with matching log groups
        """
        filter_params = filter_params or LogGroupFilter()

        logger.info(
            "Listing log groups filter=%s next_token=%s limit=%d",
            filter_params.model_dump(exclude_none=True),
            next_token,
            limit,
        )

        # If account_alias is specified, only query that account
        if filter_params.account_alias:
            adapter = self._get_adapter(account_alias=filter_params.account_alias)
            adapters = [adapter]
        else:
            # Query all configured accounts
            adapters = get_all_logs_adapters()

        all_groups: list[LogGroup] = []
        result_next_token: str | None = None

        for adapter in adapters:
            try:
                raw_groups, token = await adapter.describe_log_groups(
                    prefix=filter_params.prefix,
                    next_token=next_token,
                    limit=limit,
                )

                # Convert and filter results
                for raw in raw_groups:
                    group = self._convert_log_group(raw)

                    # Apply additional filters
                    if not self._matches_filter(group, filter_params):
                        continue

                    all_groups.append(group)

                # Keep track of pagination
                if token:
                    result_next_token = token

            except AWSAccessDeniedError as e:
                logger.warning(
                    "Access denied listing log groups account=%s: %s",
                    adapter.account_alias,
                    e,
                )
            except AWSThrottlingError as e:
                logger.warning(
                    "Throttled listing log groups account=%s: %s",
                    adapter.account_alias,
                    e,
                )
                raise

        return LogGroupListResponse(
            log_groups=all_groups[:limit],
            next_token=result_next_token,
            total_count=len(all_groups),
        )

    async def get_log_group_tags(
        self,
        log_group_name: str,
        account_alias: str | None = None,
    ) -> dict[str, str]:
        """Get tags for a specific log group."""
        adapter = self._get_adapter(account_alias=account_alias)
        return await adapter.list_tags_for_log_group(log_group_name)

    async def start_query(self, request: StartQueryRequest) -> StartQueryResponse:
        """Start a CloudWatch Logs Insights query.

        Args:
            request: Query parameters

        Returns:
            StartQueryResponse with query ID and status

        Raises:
            QueryConcurrencyError: If too many queries are running
            ValueError: If query parameters are invalid
        """
        adapter = self._get_adapter(account_alias=request.account_alias)

        # Calculate time range
        start_time, end_time = _time_range_to_epoch(request.time_range)

        logger.info(
            "Starting query account=%s groups=%d query_chars=%d window=%d-%d",
            request.account_alias,
            len(request.log_group_names),
            len(request.query_string),
            start_time,
            end_time,
        )

        # Start the query
        query_id = await adapter.start_insights_query(
            log_group_names=request.log_group_names,
            query_string=request.query_string,
            start_time=start_time,
            end_time=end_time,
            limit=request.limit,
        )

        # Track the query
        await _query_tracker.register(
            query_id=query_id,
            log_group_names=request.log_group_names,
            query_string=request.query_string,
            account_alias=request.account_alias,
        )

        return StartQueryResponse(
            query_id=query_id,
            status=QueryStatus.SCHEDULED,
            log_group_names=request.log_group_names,
            started_at=datetime.now(UTC),
        )

    async def get_query_results(
        self,
        query_id: str,
        account_alias: str | None = None,
    ) -> QueryResultsResponse:
        """Get results from a Logs Insights query.

        Args:
            query_id: The query ID returned from start_query
            account_alias: Account alias if using multi-account

        Returns:
            QueryResultsResponse with status and events
        """
        adapter = self._get_adapter(account_alias=account_alias)

        logger.debug("Getting query results query_id=%s", query_id)

        raw_results = await adapter.get_query_results(query_id)

        status_str = raw_results.get("status", "Unknown")
        try:
            status = QueryStatus(status_str)
        except ValueError:
            status = QueryStatus.UNKNOWN

        # Parse events if complete
        events: list[LogEvent] = []
        if status == QueryStatus.COMPLETE:
            for result in raw_results.get("results", []):
                event = _parse_insights_result(
                    result=result,
                    log_group="",  # Will be filled from @logGroup field
                    account_alias=account_alias,
                    region=adapter.region,
                )
                events.append(event)

            # Unregister from tracking
            await _query_tracker.unregister(query_id)

        # Parse statistics
        stats_raw = raw_results.get("statistics", {})
        statistics = QueryStatistics(
            records_matched=float(stats_raw.get("recordsMatched", 0)),
            records_scanned=float(stats_raw.get("recordsScanned", 0)),
            bytes_scanned=float(stats_raw.get("bytesScanned", 0)),
        )

        # Check scan budget
        if statistics.bytes_scanned > 0:
            self._total_bytes_scanned += statistics.bytes_scanned
            if (
                settings.cw_query_scan_limit_bytes > 0
                and self._total_bytes_scanned > settings.cw_query_scan_limit_bytes
            ):
                logger.warning(
                    "Scan budget exceeded: scanned=%d limit=%d",
                    self._total_bytes_scanned,
                    settings.cw_query_scan_limit_bytes,
                )
                raise ScanBudgetExceededError(
                    f"Scan budget exceeded: {self._total_bytes_scanned} bytes scanned, "
                    f"limit is {settings.cw_query_scan_limit_bytes} bytes"
                )

        return QueryResultsResponse(
            query_id=query_id,
            status=status,
            events=events,
            statistics=statistics,
        )

    async def poll_query_until_complete(
        self,
        query_id: str,
        account_alias: str | None = None,
        timeout_seconds: int | None = None,
    ) -> QueryResultsResponse:
        """Poll a query until it completes or times out.

        Args:
            query_id: The query ID to poll
            account_alias: Account alias if using multi-account
            timeout_seconds: Override the default timeout

        Returns:
            QueryResultsResponse with final status and events

        Raises:
            QueryTimeoutError: If the query times out
        """
        timeout = timeout_seconds or settings.cw_query_timeout_seconds
        poll_interval = settings.cw_query_poll_interval_ms / 1000.0
        start_time = time.time()

        logger.info(
            "Polling query query_id=%s timeout=%ds interval=%dms",
            query_id,
            timeout,
            settings.cw_query_poll_interval_ms,
        )

        while True:
            elapsed = time.time() - start_time
            if elapsed >= timeout:
                # Try to cancel the query
                await self.cancel_query(query_id, account_alias)
                raise QueryTimeoutError(f"Query {query_id} timed out after {elapsed:.1f}s")

            result = await self.get_query_results(query_id, account_alias)

            if result.status in {
                QueryStatus.COMPLETE,
                QueryStatus.FAILED,
                QueryStatus.CANCELLED,
            }:
                logger.info(
                    "Query finished query_id=%s status=%s elapsed=%.1fs events=%d",
                    query_id,
                    result.status.value,
                    elapsed,
                    len(result.events),
                )
                return result

            await asyncio.sleep(poll_interval)

    async def cancel_query(
        self,
        query_id: str,
        account_alias: str | None = None,
    ) -> CancelQueryResponse:
        """Cancel a running query.

        Args:
            query_id: The query ID to cancel
            account_alias: Account alias if using multi-account

        Returns:
            CancelQueryResponse with cancellation status
        """
        adapter = self._get_adapter(account_alias=account_alias)

        logger.info("Cancelling query query_id=%s", query_id)

        success = await adapter.stop_query(query_id)
        await _query_tracker.unregister(query_id)

        return CancelQueryResponse(
            query_id=query_id,
            cancelled=success,
            message="Query cancelled" if success else "Query may have already completed",
        )

    async def get_active_queries(self) -> ActiveQueriesResponse:
        """Get list of currently tracked active queries."""
        queries = await _query_tracker.get_active()
        return ActiveQueriesResponse(
            queries=queries,
            total_count=len(queries),
        )

    def _convert_log_group(self, raw: dict[str, Any]) -> LogGroup:
        """Convert raw boto3 log group to LogGroup schema."""
        creation_time = None
        if "creationTime" in raw:
            creation_time = datetime.fromtimestamp(raw["creationTime"] / 1000, UTC)

        return LogGroup(
            log_group_name=raw["logGroupName"],
            arn=raw.get("arn"),
            creation_time=creation_time,
            stored_bytes=raw.get("storedBytes"),
            retention_days=raw.get("retentionInDays"),
            kms_key_id=raw.get("kmsKeyId"),
            tags=raw.get("_tags", {}),
            account_alias=raw.get("_account_alias"),
            region=raw.get("_region"),
        )

    def _matches_filter(self, group: LogGroup, filter_params: LogGroupFilter) -> bool:
        """Check if a log group matches the given filter criteria."""
        # Name contains filter
        if (
            filter_params.name_contains
            and filter_params.name_contains.lower() not in group.log_group_name.lower()
        ):
            return False

        # Environment tag filter
        if filter_params.environment_tag:
            env_tag = group.tags.get("Environment", "").lower()
            if env_tag != filter_params.environment_tag.lower():
                return False

        # Region filter
        if filter_params.region and group.region:
            return group.region == filter_params.region

        return True


# Convenience function for backwards compatibility
class IngestionService(LogIngestionService):
    """Alias for backwards compatibility."""

    pass
