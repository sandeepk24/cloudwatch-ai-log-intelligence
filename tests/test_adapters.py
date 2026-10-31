"""AWS adapters and AI providers stay behind interfaces."""

import pytest

from app.adapters.aws.base import (
    AdapterNotImplementedError,
    AWSAccessDeniedError,
    AWSCredentialsError,
    AWSThrottlingError,
    QueryConcurrencyError,
    QueryTimeoutError,
    ScanBudgetExceededError,
)
from app.adapters.aws.factory import get_logs_adapter, get_metrics_adapter
from app.adapters.aws.logs import BotoCloudWatchLogsAdapter
from app.adapters.aws.mock import MockCloudWatchLogsAdapter, MockCloudWatchMetricsAdapter
from app.ai.base import AINotImplementedError
from app.ai.factory import get_ai_provider
from app.services.analytics import AnalyticsService
from app.services.ingestion import LogIngestionService
from app.services.reasoning import ReasoningService


# -----------------------------------------------------------------------------
# Mock Adapter Tests
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mock_logs_adapter_returns_canned_groups():
    """Test mock adapter returns log groups."""
    adapter = get_logs_adapter()
    assert adapter.mode == "mock"

    groups, next_token = await adapter.describe_log_groups()
    assert len(groups) >= 1
    assert all("logGroupName" in group for group in groups)


@pytest.mark.asyncio
async def test_mock_logs_adapter_pagination():
    """Test mock adapter pagination."""
    adapter = MockCloudWatchLogsAdapter()

    # Get first page
    groups1, token1 = await adapter.describe_log_groups(limit=2)
    assert len(groups1) <= 2

    # If there's a next token, get next page
    if token1:
        groups2, _ = await adapter.describe_log_groups(next_token=token1, limit=2)
        assert len(groups2) <= 2


@pytest.mark.asyncio
async def test_mock_logs_adapter_prefix_filter():
    """Test mock adapter filters by prefix."""
    adapter = MockCloudWatchLogsAdapter()

    groups, _ = await adapter.describe_log_groups(prefix="/aws/ecs/")
    assert all(g["logGroupName"].startswith("/aws/ecs/") for g in groups)


@pytest.mark.asyncio
async def test_mock_logs_adapter_tags():
    """Test mock adapter returns tags."""
    adapter = MockCloudWatchLogsAdapter()

    tags = await adapter.list_tags_for_log_group("/aws/ecs/prod-api")
    assert isinstance(tags, dict)
    assert "Environment" in tags


@pytest.mark.asyncio
async def test_mock_logs_adapter_query_lifecycle():
    """Test mock adapter query start/poll/complete."""
    adapter = MockCloudWatchLogsAdapter()

    # Start query
    query_id = await adapter.start_insights_query(
        log_group_names=["/aws/ecs/prod-api"],
        query_string="fields @timestamp, @message | limit 10",
        start_time=1000000000,
        end_time=1000003600,
    )
    assert query_id.startswith("mock-")

    # Poll until complete (mock completes after a few polls)
    for _ in range(10):
        result = await adapter.get_query_results(query_id)
        assert "status" in result
        assert "queryId" in result

        if result["status"] == "Complete":
            assert "results" in result
            assert "statistics" in result
            break


@pytest.mark.asyncio
async def test_mock_logs_adapter_stop_query():
    """Test mock adapter can stop a query."""
    adapter = MockCloudWatchLogsAdapter()

    query_id = await adapter.start_insights_query(
        log_group_names=["/aws/ecs/prod-api"],
        query_string="fields @timestamp | limit 10",
        start_time=1000000000,
        end_time=1000003600,
    )

    stopped = await adapter.stop_query(query_id)
    assert stopped is True


@pytest.mark.asyncio
async def test_mock_logs_adapter_describe_queries():
    """Test mock adapter lists queries."""
    adapter = MockCloudWatchLogsAdapter()

    # Start a query first
    await adapter.start_insights_query(
        log_group_names=["/aws/ecs/prod-api"],
        query_string="fields @timestamp | limit 10",
        start_time=1000000000,
        end_time=1000003600,
    )

    queries = await adapter.describe_queries()
    assert isinstance(queries, list)


@pytest.mark.asyncio
async def test_mock_metrics_adapter_returns_canned_series():
    """Test mock metrics adapter returns data."""
    adapter = get_metrics_adapter()
    assert adapter.mode == "mock"

    data = await adapter.get_metric_data("CPUUtilization", "AWS/ECS")
    assert data["status"] == "Complete"
    assert data["values"]


# -----------------------------------------------------------------------------
# Service Tests
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ingestion_service_uses_mock_adapter():
    """Test ingestion service works with mock adapter."""
    service = LogIngestionService()
    result = await service.list_log_groups()

    assert result.log_groups
    assert result.log_groups[0].log_group_name.startswith("/aws/")


@pytest.mark.asyncio
async def test_ingestion_service_filters_by_prefix():
    """Test ingestion service prefix filtering."""
    from app.schemas.logs import LogGroupFilter

    service = LogIngestionService()
    filter_params = LogGroupFilter(prefix="/aws/ecs/")
    result = await service.list_log_groups(filter_params=filter_params)

    for group in result.log_groups:
        assert group.log_group_name.startswith("/aws/ecs/")


@pytest.mark.asyncio
async def test_ingestion_service_filters_by_name_contains():
    """Test ingestion service name substring filtering."""
    from app.schemas.logs import LogGroupFilter

    service = LogIngestionService()
    filter_params = LogGroupFilter(name_contains="prod")
    result = await service.list_log_groups(filter_params=filter_params)

    for group in result.log_groups:
        assert "prod" in group.log_group_name.lower()


@pytest.mark.asyncio
async def test_ingestion_service_start_query():
    """Test ingestion service can start a query."""
    from app.schemas.logs import StartQueryRequest, TimeRange, TimeRangePreset

    service = LogIngestionService()
    request = StartQueryRequest(
        log_group_names=["/aws/ecs/prod-api"],
        query_string="fields @timestamp, @message | limit 10",
        time_range=TimeRange(preset=TimeRangePreset.LAST_1_HOUR),
    )

    result = await service.start_query(request)
    assert result.query_id
    assert result.status.value in ["Scheduled", "Running"]


@pytest.mark.asyncio
async def test_ingestion_service_poll_query():
    """Test ingestion service can poll a query to completion."""
    from app.schemas.logs import StartQueryRequest

    service = LogIngestionService()
    request = StartQueryRequest(
        log_group_names=["/aws/ecs/prod-api"],
        query_string="fields @timestamp, @message | limit 10",
    )

    start_result = await service.start_query(request)
    result = await service.poll_query_until_complete(
        query_id=start_result.query_id,
        timeout_seconds=30,
    )

    assert result.status.value == "Complete"
    assert result.statistics is not None


@pytest.mark.asyncio
async def test_analytics_service_is_skeleton():
    """Test analytics service returns skeleton status."""
    result = await AnalyticsService().summarize([{"message": "error"}])
    assert result["status"] == "skeleton"
    assert result["event_count"] == 1


# -----------------------------------------------------------------------------
# AI Provider Tests
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_default_provider_is_bedrock_stub():
    """Test default AI provider is Bedrock."""
    provider = get_ai_provider()
    assert provider.name == "bedrock"
    assert await provider.is_available() is False
    with pytest.raises(AINotImplementedError):
        await provider.generate("summarize this incident")


@pytest.mark.asyncio
async def test_strands_provider_stub():
    """Test Strands provider is a stub."""
    provider = get_ai_provider("strands")
    assert provider.name == "strands"
    assert await provider.is_available() is False
    with pytest.raises(AINotImplementedError):
        await provider.generate("unused")


@pytest.mark.asyncio
async def test_reasoning_service_does_not_call_a_model():
    """Test reasoning service is a skeleton."""
    result = await ReasoningService().explain({"events": []})
    assert result["status"] == "skeleton"
    assert result["summary"] is None


# -----------------------------------------------------------------------------
# Exception Tests
# -----------------------------------------------------------------------------


def test_exception_classes_exist():
    """Test custom exception classes are defined."""
    # Just make sure they can be instantiated
    e1 = AWSThrottlingError("throttled", retry_after_seconds=5)
    assert e1.retry_after_seconds == 5

    e2 = AWSCredentialsError("invalid credentials")
    assert str(e2) == "invalid credentials"

    e3 = AWSAccessDeniedError("denied", resource="arn:aws:logs:...")
    assert e3.resource == "arn:aws:logs:..."

    e4 = QueryTimeoutError("timeout")
    e5 = QueryConcurrencyError("too many")
    e6 = ScanBudgetExceededError("budget exceeded")

    assert all([e4, e5, e6])
