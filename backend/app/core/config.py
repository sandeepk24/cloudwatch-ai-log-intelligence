"""Application configuration using Pydantic Settings.

AWS credentials are never loaded here. When mock mode is off, adapters use the
standard boto3 credential chain (environment, shared config, instance/task role).
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class AWSAccountConfig(BaseSettings):
    """Configuration for an external AWS account accessed via assume role."""

    model_config = SettingsConfigDict(extra="ignore")

    account_alias: str = ""
    role_arn: str = ""
    external_id: str = ""
    region: str = ""


class Settings(BaseSettings):
    """Settings loaded from environment variables and an optional .env file."""

    model_config = SettingsConfigDict(
        env_file="../.env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "CloudWatch AI Log Intelligence"
    app_version: str = "0.1.0"
    backend_host: str = "0.0.0.0"
    backend_port: int = 8000
    backend_log_level: str = "info"
    log_format: str = "json"

    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:8080"]

    # AWS core settings
    aws_region: str = ""
    aws_use_mock: bool = True

    # CloudWatch Logs query settings
    cw_query_timeout_seconds: int = Field(default=60, ge=5, le=300)
    cw_query_max_concurrency: int = Field(default=5, ge=1, le=20)
    cw_query_poll_interval_ms: int = Field(default=500, ge=100, le=5000)
    cw_query_max_log_groups: int = Field(default=50, ge=1, le=50)
    cw_query_scan_limit_bytes: int = Field(default=10_000_000_000, ge=0)  # 10GB default
    cw_log_groups_page_size: int = Field(default=50, ge=1, le=50)

    # Multi-account support: JSON array of account configs
    # Format: [{"account_alias":"prod","role_arn":"arn:aws:iam::123456789012:role/ReadOnly","external_id":"","region":"us-east-1"}]
    aws_accounts: str = "[]"

    # AI provider settings
    ai_provider: str = "bedrock"
    bedrock_enabled: bool = False
    bedrock_model_id: str = "anthropic.claude-3-5-sonnet-20241022-v2:0"
    strands_enabled: bool = False

    @property
    def resolved_aws_region(self) -> str | None:
        """Return a configured region, or None so boto3 uses its default chain."""
        value = self.aws_region.strip()
        return value or None

    @property
    def aws_mode(self) -> str:
        return "mock" if self.aws_use_mock else "live"

    @property
    def bedrock_configured(self) -> bool:
        return self.bedrock_enabled and bool(self.bedrock_model_id.strip())

    @property
    def strands_configured(self) -> bool:
        return self.strands_enabled

    def get_configured_accounts(self) -> list[AWSAccountConfig]:
        """Parse the JSON array of configured AWS accounts."""
        import json

        try:
            raw = json.loads(self.aws_accounts)
            if not isinstance(raw, list):
                return []
            return [AWSAccountConfig(**item) for item in raw if isinstance(item, dict)]
        except (json.JSONDecodeError, TypeError):
            return []


settings = Settings()
