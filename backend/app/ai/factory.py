"""Select an AI provider from configuration."""

from app.ai.base import AIProvider
from app.ai.bedrock import BedrockProvider
from app.ai.strands import StrandsProvider
from app.core.config import settings


def get_ai_provider(name: str | None = None) -> AIProvider:
    selected = (name or settings.ai_provider).strip().lower()
    if selected == "strands":
        return StrandsProvider()
    return BedrockProvider()
