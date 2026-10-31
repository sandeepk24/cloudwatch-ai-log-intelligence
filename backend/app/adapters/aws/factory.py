"""Select mock or live AWS adapters from configuration."""

from app.adapters.aws.base import CloudWatchLogsPort, CloudWatchMetricsPort
from app.adapters.aws.logs import BotoCloudWatchLogsAdapter
from app.adapters.aws.metrics import BotoCloudWatchMetricsAdapter
from app.adapters.aws.mock import MockCloudWatchLogsAdapter, MockCloudWatchMetricsAdapter
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


def get_logs_adapter() -> CloudWatchLogsPort:
    if settings.aws_use_mock:
        logger.debug("Using mock CloudWatch Logs adapter")
        return MockCloudWatchLogsAdapter()
    logger.debug("Using live CloudWatch Logs adapter")
    return BotoCloudWatchLogsAdapter()


def get_metrics_adapter() -> CloudWatchMetricsPort:
    if settings.aws_use_mock:
        logger.debug("Using mock CloudWatch Metrics adapter")
        return MockCloudWatchMetricsAdapter()
    logger.debug("Using live CloudWatch Metrics adapter")
    return BotoCloudWatchMetricsAdapter()
