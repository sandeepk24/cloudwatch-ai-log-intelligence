"""Strands Agents adapter — configuration only in this milestone."""

from app.ai.base import AINotImplementedError
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class StrandsProvider:
    name = "strands"

    async def is_available(self) -> bool:
        configured = settings.strands_configured
        logger.debug("Strands configured=%s", configured)
        return configured

    async def generate(self, prompt: str, *, system: str | None = None) -> str:
        raise AINotImplementedError(
            "Strands Agents runtime is not implemented in this milestone "
            f"(prompt_chars={len(prompt)}, system_set={system is not None})."
        )
