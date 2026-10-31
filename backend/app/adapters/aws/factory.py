"""Select mock or live AWS adapters from configuration."""

from __future__ import annotations

from functools import lru_cache

from app.adapters.aws.base import CloudWatchLogsPort, CloudWatchMetricsPort
from app.adapters.aws.logs import BotoCloudWatchLogsAdapter
from app.adapters.aws.metrics import BotoCloudWatchMetricsAdapter
from app.adapters.aws.mock import MockCloudWatchLogsAdapter, MockCloudWatchMetricsAdapter
from app.core.config import AWSAccountConfig, settings
from app.core.logging import get_logger

logger = get_logger(__name__)


def get_logs_adapter(
    account_alias: str | None = None,
    region: str | None = None,
) -> CloudWatchLogsPort:
    """Get a CloudWatch Logs adapter.

    Args:
        account_alias: If provided, use the configured account's IAM role.
                      If None, use the default credential chain.
        region: Override the AWS region.

    Returns:
        A CloudWatch Logs adapter (mock or live based on settings).
    """
    if settings.aws_use_mock:
        logger.debug("Using mock CloudWatch Logs adapter alias=%s", account_alias)
        return MockCloudWatchLogsAdapter(account_alias=account_alias, region=region)

    # Check if this is a configured external account
    if account_alias:
        account_config = _get_account_config(account_alias)
        if account_config:
            logger.debug(
                "Using live CloudWatch Logs adapter with assumed role alias=%s",
                account_alias,
            )
            return BotoCloudWatchLogsAdapter(
                account_alias=account_alias,
                role_arn=account_config.role_arn,
                external_id=account_config.external_id or None,
                region=region or account_config.region or None,
            )
        else:
            raise ValueError(
                f"Unknown account alias: {account_alias}. "
                f"Configure it in AWS_ACCOUNTS or use the default account."
            )

    logger.debug("Using live CloudWatch Logs adapter with default credentials")
    return BotoCloudWatchLogsAdapter(
        account_alias=None,
        region=region,
    )


def get_metrics_adapter() -> CloudWatchMetricsPort:
    """Get a CloudWatch Metrics adapter."""
    if settings.aws_use_mock:
        logger.debug("Using mock CloudWatch Metrics adapter")
        return MockCloudWatchMetricsAdapter()
    logger.debug("Using live CloudWatch Metrics adapter")
    return BotoCloudWatchMetricsAdapter()


@lru_cache(maxsize=1)
def _get_configured_accounts() -> dict[str, AWSAccountConfig]:
    """Get a dictionary of configured accounts keyed by alias."""
    accounts = settings.get_configured_accounts()
    return {acc.account_alias: acc for acc in accounts if acc.account_alias}


def _get_account_config(account_alias: str) -> AWSAccountConfig | None:
    """Get configuration for a specific account alias."""
    accounts = _get_configured_accounts()
    return accounts.get(account_alias)


def list_configured_accounts() -> list[str]:
    """List all configured account aliases."""
    accounts = _get_configured_accounts()
    return list(accounts.keys())


def get_all_logs_adapters() -> list[CloudWatchLogsPort]:
    """Get adapters for all configured accounts plus the default.

    This is useful for operations that need to query across all accounts.
    """
    adapters: list[CloudWatchLogsPort] = []

    # Default account
    adapters.append(get_logs_adapter())

    # Configured accounts
    for alias in list_configured_accounts():
        try:
            adapters.append(get_logs_adapter(account_alias=alias))
        except Exception as e:
            logger.warning("Failed to create adapter for account %s: %s", alias, e)

    return adapters
