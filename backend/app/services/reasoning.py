"""AI incident reasoning. Model invocation is not implemented yet."""

from __future__ import annotations

from typing import Any

from app.ai.base import AIProvider
from app.ai.factory import get_ai_provider
from app.core.logging import get_logger

logger = get_logger(__name__)


class ReasoningService:
    def __init__(self, provider: AIProvider | None = None) -> None:
        self._provider = provider or get_ai_provider()

    async def explain(self, evidence: dict[str, Any]) -> dict[str, Any]:
        logger.info(
            "Reasoning explain called provider=%s evidence_keys=%s (skeleton)",
            self._provider.name,
            sorted(evidence.keys()),
        )
        available = await self._provider.is_available()
        return {
            "status": "skeleton",
            "provider": self._provider.name,
            "available": available,
            "summary": None,
        }
