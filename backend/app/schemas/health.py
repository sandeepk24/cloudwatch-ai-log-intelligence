"""Health, readiness, capabilities, and non-secret settings."""

from pydantic import BaseModel, Field


class LivenessResponse(BaseModel):
    """Bare liveness payload for load balancers (`GET /health`)."""

    status: str
    version: str


class HealthData(BaseModel):
    status: str
    version: str
    aws_mode: str
    aws_region: str | None = None
    ai_provider: str
    bedrock_configured: bool
    strands_configured: bool
    mock_aws: bool


class ReadyData(BaseModel):
    status: str


class ModuleStatus(BaseModel):
    status: str
    detail: str


class CapabilitiesData(BaseModel):
    ingestion: ModuleStatus
    analytics: ModuleStatus
    correlation: ModuleStatus
    reasoning: ModuleStatus


class SettingsData(BaseModel):
    app_name: str
    app_version: str
    aws_mode: str
    aws_region: str | None = None
    aws_use_mock: bool
    ai_provider: str
    bedrock_enabled: bool
    bedrock_model_id: str
    bedrock_configured: bool
    strands_enabled: bool
    strands_configured: bool
    cors_origins: list[str] = Field(default_factory=list)
