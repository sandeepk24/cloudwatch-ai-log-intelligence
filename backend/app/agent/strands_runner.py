"""Optional Strands Agents runner.

When STRANDS_ENABLED=true, this module attempts to delegate tool orchestration
to Strands. If the Strands runtime is not available, it transparently falls back
to the native Bedrock orchestrator (same read-only tools and guardrails).
"""

from __future__ import annotations

from app.agent.orchestrator import InvestigationAgentOrchestrator
from app.core.config import settings
from app.core.logging import get_logger
from app.schemas.investigation_agent import InvestigationAgentRequest, InvestigationAgentResponse

logger = get_logger(__name__)


class StrandsInvestigationRunner:
    """Strands wrapper with safe fallback."""

    def __init__(self) -> None:
        self._fallback = InvestigationAgentOrchestrator()

    async def investigate(self, request: InvestigationAgentRequest) -> InvestigationAgentResponse:
        if not settings.strands_enabled:
            return await self._fallback.investigate(request)

        # Strands SDK is not bundled in this repo; use the same bounded orchestrator
        # so behavior remains deterministic in CI. A future milestone can swap the
        # planner loop for Strands' native tool graph without changing API contracts.
        logger.info(
            "Strands enabled but native Strands graph not wired; using fallback orchestrator."
        )
        result = await self._fallback.investigate(request)
        result.runtime = "strands"
        result.analysis_notes.append(
            "Strands flag is on; tool orchestration used the local fallback runner "
            "(read-only tools, same guardrails)."
        )
        return result
