"""Tests for AWS session and credential handling."""

from app.adapters.aws import session as aws_session
from app.core.config import Settings


def test_session_helpers_are_importable():
    """Test session helpers can be imported."""
    assert callable(aws_session.build_session)
    assert callable(aws_session.build_assumed_session)
    assert callable(aws_session.credentials_present)
    assert callable(aws_session.get_caller_identity)


def test_build_session_returns_session():
    """Test build_session returns a boto3 session."""
    session = aws_session.build_session()
    assert hasattr(session, "client")
    assert hasattr(session, "get_credentials")


def test_credentials_present_returns_bool():
    """Test credentials_present returns a boolean."""
    result = aws_session.credentials_present()
    assert isinstance(result, bool)


def test_get_caller_identity_handles_missing_creds():
    """Test get_caller_identity handles missing credentials gracefully."""
    # This may return None if no credentials are configured
    result = aws_session.get_caller_identity()
    assert result is None or isinstance(result, dict)


def test_settings_aws_accounts_parsing():
    """Test parsing of AWS_ACCOUNTS configuration."""
    # Empty array
    settings = Settings(aws_accounts="[]")
    assert settings.get_configured_accounts() == []

    # Single account
    settings = Settings(
        aws_accounts='[{"account_alias":"prod","role_arn":"arn:aws:iam::123:role/Test"}]'
    )
    accounts = settings.get_configured_accounts()
    assert len(accounts) == 1
    assert accounts[0].account_alias == "prod"
    assert accounts[0].role_arn == "arn:aws:iam::123:role/Test"

    # Multiple accounts
    settings = Settings(
        aws_accounts='[{"account_alias":"prod","role_arn":"arn:1","region":"us-east-1"},{"account_alias":"staging","role_arn":"arn:2"}]'
    )
    accounts = settings.get_configured_accounts()
    assert len(accounts) == 2
    assert accounts[0].region == "us-east-1"
    assert accounts[1].region == ""


def test_settings_invalid_aws_accounts_returns_empty():
    """Test invalid AWS_ACCOUNTS returns empty list."""
    settings = Settings(aws_accounts="invalid json")
    assert settings.get_configured_accounts() == []

    settings = Settings(aws_accounts='{"not":"an array"}')
    assert settings.get_configured_accounts() == []


def test_settings_query_limits():
    """Test query limit settings have valid defaults."""
    settings = Settings()

    assert 5 <= settings.cw_query_timeout_seconds <= 300
    assert 1 <= settings.cw_query_max_concurrency <= 20
    assert 100 <= settings.cw_query_poll_interval_ms <= 5000
    assert 1 <= settings.cw_query_max_log_groups <= 50
    assert settings.cw_query_scan_limit_bytes >= 0
