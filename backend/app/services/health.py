"""Health and settings assembly. Does not query CloudWatch or invoke models."""

from app.adapters.aws.factory import get_logs_adapter, get_metrics_adapter
from app.ai.factory import get_ai_provider
from app.core.config import settings
from app.schemas.health import (
    CapabilitiesData,
    HealthData,
    ModuleStatus,
    ReadyData,
    SettingsData,
)


async def build_health() -> HealthData:
    logs = get_logs_adapter()
    metrics = get_metrics_adapter()
    provider = get_ai_provider()
    return HealthData(
        status="healthy",
        version=settings.app_version,
        aws_mode=logs.mode,
        aws_region=settings.resolved_aws_region,
        ai_provider=provider.name,
        bedrock_configured=settings.bedrock_configured,
        strands_configured=settings.strands_configured,
        mock_aws=logs.mode == "mock" and metrics.mode == "mock",
    )


def build_ready() -> ReadyData:
    return ReadyData(status="ready")


def build_capabilities() -> CapabilitiesData:
    return CapabilitiesData(
        ingestion=ModuleStatus(
            status="skeleton",
            detail="CloudWatch Logs Insights adapter is present; query engine is not wired",
        ),
        analytics=ModuleStatus(
            status="skeleton",
            detail="Error clustering and burst detection are not implemented",
        ),
        correlation=ModuleStatus(
            status="skeleton",
            detail="Log-to-metric correlation is not implemented",
        ),
        reasoning=ModuleStatus(
            status="skeleton",
            detail="Bedrock and Strands providers are stubs in this milestone",
        ),
    )


def build_settings() -> SettingsData:
    return SettingsData(
        app_name=settings.app_name,
        app_version=settings.app_version,
        aws_mode=settings.aws_mode,
        aws_region=settings.resolved_aws_region,
        aws_use_mock=settings.aws_use_mock,
        ai_provider=settings.ai_provider,
        bedrock_enabled=settings.bedrock_enabled,
        bedrock_model_id=settings.bedrock_model_id,
        bedrock_configured=settings.bedrock_configured,
        strands_enabled=settings.strands_enabled,
        strands_configured=settings.strands_configured,
        cors_origins=list(settings.cors_origins),
    )
