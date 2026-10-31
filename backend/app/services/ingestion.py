"""CloudWatch log ingestion orchestration. Query engine is not implemented yet."""

from __future__ import annotations

from typing import Any

from app.adapters.aws.base import CloudWatchLogsPort
from app.adapters.aws.factory import get_logs_adapter
from app.core.logging import get_logger

logger = get_logger(__name__)


class IngestionService:
    def __init__(self, logs: CloudWatchLogsPort | None = None) -> None:
        self._logs = logs or get_logs_adapter()

    async def list_log_groups(self, prefix: str | None = None) -> list[dict[str, Any]]:
        logger.info("Listing log groups mode=%s prefix=%s", self._logs.mode, prefix)
        return await self._logs.describe_log_groups(prefix)
