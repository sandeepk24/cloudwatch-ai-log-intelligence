"""Configuration must not hardcode account numbers or credentials."""

from pathlib import Path

from app.core.config import Settings


def test_default_settings_use_mock_aws():
    settings = Settings()
    assert settings.aws_use_mock is True
    assert settings.resolved_aws_region is None
    assert settings.aws_mode == "mock"


def test_env_example_has_no_credentials():
    example = Path(__file__).resolve().parents[1].joinpath(".env.example").read_text()
    lowered = example.lower()
    assert "aws_access_key_id" not in lowered
    assert "aws_secret_access_key" not in lowered
    assert "akia" not in lowered
