"""Amazon Bedrock adapter — configuration only in this milestone."""

from app.ai.base import AINotImplementedError
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class BedrockProvider:
    name = "bedrock"

    async def is_available(self) -> bool:
        configured = settings.bedrock_configured
        logger.debug("Bedrock configured=%s region=%s", configured, settings.resolved_aws_region)
        return configured

    async def generate(self, prompt: str, *, system: str | None = None) -> str:
        raise AINotImplementedError(
            "Amazon Bedrock inference is not implemented in this milestone "
            f"(prompt_chars={len(prompt)}, system_set={system is not None})."
        )
