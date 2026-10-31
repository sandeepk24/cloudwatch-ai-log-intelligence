"""Schemas for CloudWatch Logs discovery and queries."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# -----------------------------------------------------------------------------
# Time Range
# -----------------------------------------------------------------------------


class TimeRangePreset(StrEnum):
    """Preset time windows for log queries."""

    LAST_15_MINUTES = "15m"
    LAST_1_HOUR = "1h"
    LAST_6_HOURS = "6h"
    LAST_24_HOURS = "24h"
    CUSTOM = "custom"


class TimeRange(BaseModel):
    """Time range for log queries. Use preset or custom start/end."""

    preset: TimeRangePreset = TimeRangePreset.LAST_1_HOUR
    start_time: datetime | None = None
    end_time: datetime | None = None


# -----------------------------------------------------------------------------
# Log Group Discovery
# -----------------------------------------------------------------------------


class LogGroupFilter(BaseModel):
    """Filters for log group discovery."""

    prefix: str | None = Field(default=None, max_length=512)
    account_alias: str | None = Field(default=None, max_length=128)
    region: str | None = Field(default=None, max_length=32)
    environment_tag: str | None = Field(default=None, max_length=256)
    name_contains: str | None = Field(default=None, max_length=256)


class LogGroup(BaseModel):
    """Normalized log group representation."""

    log_group_name: str
    arn: str | None = None
    creation_time: datetime | None = None
    stored_bytes: int | None = None
    retention_days: int | None = None
    kms_key_id: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)
    account_alias: str | None = None
    region: str | None = None


class LogGroupListResponse(BaseModel):
    """Response for log group listing."""

    log_groups: list[LogGroup]
    next_token: str | None = None
    total_count: int | None = None


# -----------------------------------------------------------------------------
# Log Events
# -----------------------------------------------------------------------------


class LogEvent(BaseModel):
    """Normalized log event from CloudWatch Logs."""

    timestamp: datetime
    message: str
    log_group: str
    log_stream: str | None = None
    ingestion_time: datetime | None = None
    event_id: str | None = None
    ptr: str | None = None  # CloudWatch Logs pointer for deep linking
    account_alias: str | None = None
    region: str | None = None
    raw_fields: dict[str, Any] = Field(default_factory=dict)


# -----------------------------------------------------------------------------
# Insights Query
# -----------------------------------------------------------------------------


class QueryStatus(StrEnum):
    """CloudWatch Logs Insights query status."""

    SCHEDULED = "Scheduled"
    RUNNING = "Running"
    COMPLETE = "Complete"
    FAILED = "Failed"
    CANCELLED = "Cancelled"
    TIMEOUT = "Timeout"
    UNKNOWN = "Unknown"


class StartQueryRequest(BaseModel):
    """Request to start a CloudWatch Logs Insights query."""

    log_group_names: list[str] = Field(..., min_length=1, max_length=50)
    query_string: str = Field(..., min_length=1, max_length=10000)
    time_range: TimeRange = Field(default_factory=TimeRange)
    limit: int = Field(default=1000, ge=1, le=10000)
    account_alias: str | None = Field(default=None, max_length=128)


class StartQueryResponse(BaseModel):
    """Response after starting a query."""

    query_id: str
    status: QueryStatus = QueryStatus.SCHEDULED
    log_group_names: list[str]
    started_at: datetime


class QueryResultsRequest(BaseModel):
    """Request to get query results."""

    query_id: str = Field(..., min_length=1, max_length=256)
    account_alias: str | None = Field(default=None, max_length=128)


class QueryStatistics(BaseModel):
    """Statistics about a completed query."""

    records_matched: float = 0
    records_scanned: float = 0
    bytes_scanned: float = 0


class QueryResultsResponse(BaseModel):
    """Response containing query results."""

    query_id: str
    status: QueryStatus
    events: list[LogEvent] = Field(default_factory=list)
    statistics: QueryStatistics | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None


class CancelQueryRequest(BaseModel):
    """Request to cancel a running query."""

    query_id: str = Field(..., min_length=1, max_length=256)
    account_alias: str | None = Field(default=None, max_length=128)


class CancelQueryResponse(BaseModel):
    """Response after cancelling a query."""

    query_id: str
    cancelled: bool
    message: str | None = None


# -----------------------------------------------------------------------------
# Active Queries
# -----------------------------------------------------------------------------


class ActiveQuery(BaseModel):
    """An active query being tracked."""

    query_id: str
    log_group_names: list[str]
    query_string: str
    status: QueryStatus
    started_at: datetime
    account_alias: str | None = None


class ActiveQueriesResponse(BaseModel):
    """Response listing active queries."""

    queries: list[ActiveQuery]
    total_count: int
