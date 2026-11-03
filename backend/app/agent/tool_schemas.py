"""Strict JSON schemas for investigation agent tools (inputs + outputs)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.schemas.logs import TimeRangePreset

ALLOWED_TOOLS: frozenset[str] = frozenset(
    {
        "search_cloudwatch_logs",
        "get_grouped_error_patterns",
        "get_anomaly_summaries",
        "get_cloudwatch_metrics",
        "get_deployment_metadata",
    }
)


class SearchCloudWatchLogsInput(BaseModel):
    log_group_names: list[str] = Field(..., min_length=1, max_length=10)
    query_string: str = Field(
        ...,
        min_length=1,
        max_length=2000,
        description="CloudWatch Logs Insights query; must include a limit.",
    )
    time_range_preset: TimeRangePreset = TimeRangePreset.LAST_1_HOUR
    start_time: datetime | None = None
    end_time: datetime | None = None
    account_alias: str | None = Field(default=None, max_length=128)
    limit: int = Field(default=100, ge=1, le=500)

    @field_validator("query_string")
    @classmethod
    def must_include_limit(cls, v: str) -> str:
        if "limit" not in v.lower():
            raise ValueError("query_string must include an explicit limit clause")
        return v


class SearchCloudWatchLogsOutput(BaseModel):
    event_count: int
    events: list[dict[str, Any]] = Field(default_factory=list)
    truncated: bool = False


class GroupedErrorPatternsInput(BaseModel):
    log_group_names: list[str] = Field(..., min_length=1, max_length=10)
    time_range_preset: TimeRangePreset = TimeRangePreset.LAST_1_HOUR
    start_time: datetime | None = None
    end_time: datetime | None = None
    account_alias: str | None = None
    min_occurrences: int = Field(default=2, ge=1, le=1000)


class PatternRow(BaseModel):
    pattern: str = Field(max_length=500)
    occurrence_count: int
    severity: str
    sample_log_group: str | None = None


class GroupedErrorPatternsOutput(BaseModel):
    pattern_count: int
    patterns: list[PatternRow] = Field(default_factory=list)


class AnomalySummariesInput(BaseModel):
    log_group_names: list[str] = Field(..., min_length=1, max_length=10)
    time_range_preset: TimeRangePreset = TimeRangePreset.LAST_1_HOUR
    start_time: datetime | None = None
    end_time: datetime | None = None
    account_alias: str | None = None
    bucket_minutes: int = Field(default=5, ge=1, le=60)


class AnomalySummariesOutput(BaseModel):
    status: str
    notes: list[str] = Field(default_factory=list)
    error_rate_spikes: list[dict[str, Any]] = Field(default_factory=list)
    recurring_warnings: list[dict[str, Any]] = Field(default_factory=list)


class CloudWatchMetricsInput(BaseModel):
    namespace: str = Field(..., min_length=1, max_length=256)
    metric_name: str = Field(..., min_length=1, max_length=256)
    dimensions: dict[str, str] = Field(default_factory=dict, max_length=10)
    period_seconds: int = Field(default=300, ge=60, le=3600)
    stat: str = Field(default="Average", pattern=r"^(Average|Sum|Maximum|Minimum)$")
    time_range_preset: TimeRangePreset = TimeRangePreset.LAST_1_HOUR
    start_time: datetime | None = None
    end_time: datetime | None = None


class CloudWatchMetricsOutput(BaseModel):
    namespace: str
    metric_name: str
    datapoint_count: int
    values: list[float] = Field(default_factory=list)
    timestamps: list[str] = Field(default_factory=list)


class DeploymentMetadataInput(BaseModel):
    log_group_names: list[str] = Field(..., min_length=1, max_length=10)
    time_range_preset: TimeRangePreset = TimeRangePreset.LAST_6_HOURS
    start_time: datetime | None = None
    end_time: datetime | None = None
    account_alias: str | None = None
    service_name_hint: str | None = Field(default=None, max_length=128)


class DeploymentRecord(BaseModel):
    service_name: str
    version: str | None = None
    deployed_at: datetime | None = None
    source: str
    excerpt: str = Field(max_length=500)
    log_group: str | None = None
    ptr: str | None = None


class DeploymentMetadataOutput(BaseModel):
    deployment_count: int
    deployments: list[DeploymentRecord] = Field(default_factory=list)


TOOL_INPUT_MODELS: dict[str, type[BaseModel]] = {
    "search_cloudwatch_logs": SearchCloudWatchLogsInput,
    "get_grouped_error_patterns": GroupedErrorPatternsInput,
    "get_anomaly_summaries": AnomalySummariesInput,
    "get_cloudwatch_metrics": CloudWatchMetricsInput,
    "get_deployment_metadata": DeploymentMetadataInput,
}
