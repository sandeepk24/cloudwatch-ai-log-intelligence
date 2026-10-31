"""AI provider protocol. Concrete backends must not leak into API handlers."""

from __future__ import annotations

from typing import Protocol, runtime_checkable


class AINotImplementedError(NotImplementedError):
    """Raised when a provider method is not wired yet."""


@runtime_checkable
class AIProvider(Protocol):
    """Swap Bedrock and Strands without changing services or routes."""

    name: str

    async def is_available(self) -> bool:
        """Return True when the provider is configured (not that inference works)."""
        ...

    async def generate(self, prompt: str, *, system: str | None = None) -> str:
        """Reserved for a later milestone. Must not call a model in this foundation."""
        ...
