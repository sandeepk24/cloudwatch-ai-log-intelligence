"""Application configuration using Pydantic Settings.

AWS credentials are never loaded here. When mock mode is off, adapters use the
standard boto3 credential chain (environment, shared config, instance/task role).
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


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

    aws_region: str = ""
    aws_use_mock: bool = True

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


settings = Settings()
