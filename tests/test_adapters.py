"""AWS adapters and AI providers stay behind interfaces in this milestone."""

import pytest

from app.adapters.aws.base import AdapterNotImplementedError
from app.adapters.aws.factory import get_logs_adapter, get_metrics_adapter
from app.adapters.aws.logs import BotoCloudWatchLogsAdapter
from app.ai.base import AINotImplementedError
from app.ai.factory import get_ai_provider
from app.services.analytics import AnalyticsService
from app.services.ingestion import IngestionService
from app.services.reasoning import ReasoningService


@pytest.mark.asyncio
async def test_mock_logs_adapter_returns_canned_groups():
    adapter = get_logs_adapter()
    assert adapter.mode == "mock"
    groups = await adapter.describe_log_groups()
    assert len(groups) >= 1
    assert all("logGroupName" in group for group in groups)


@pytest.mark.asyncio
async def test_mock_metrics_adapter_returns_canned_series():
    adapter = get_metrics_adapter()
    assert adapter.mode == "mock"
    data = await adapter.get_metric_data("CPUUtilization", "AWS/ECS")
    assert data["status"] == "Complete"
    assert data["values"]


@pytest.mark.asyncio
async def test_ingestion_service_uses_mock_adapter():
    service = IngestionService()
    groups = await service.list_log_groups(prefix="/aws/ecs")
    assert groups
    assert groups[0]["logGroupName"].startswith("/aws/ecs")


@pytest.mark.asyncio
async def test_analytics_service_is_skeleton():
    result = await AnalyticsService().summarize([{"message": "error"}])
    assert result["status"] == "skeleton"
    assert result["event_count"] == 1


@pytest.mark.asyncio
async def test_default_provider_is_bedrock_stub():
    provider = get_ai_provider()
    assert provider.name == "bedrock"
    assert await provider.is_available() is False
    with pytest.raises(AINotImplementedError):
        await provider.generate("summarize this incident")


@pytest.mark.asyncio
async def test_strands_provider_stub():
    provider = get_ai_provider("strands")
    assert provider.name == "strands"
    assert await provider.is_available() is False
    with pytest.raises(AINotImplementedError):
        await provider.generate("unused")


@pytest.mark.asyncio
async def test_reasoning_service_does_not_call_a_model():
    result = await ReasoningService().explain({"events": []})
    assert result["status"] == "skeleton"
    assert result["summary"] is None


@pytest.mark.asyncio
async def test_live_logs_adapter_is_not_wired():
    adapter = BotoCloudWatchLogsAdapter()
    with pytest.raises(AdapterNotImplementedError):
        await adapter.describe_log_groups()
