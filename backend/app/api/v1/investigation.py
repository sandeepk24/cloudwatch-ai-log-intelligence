"""AI Log Investigation Agent API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status

from app.agent.strands_runner import StrandsInvestigationRunner
from app.core.config import settings
from app.core.logging import get_logger
from app.core.responses import ok
from app.schemas.common import Envelope
from app.schemas.investigation_agent import InvestigationAgentRequest, InvestigationAgentResponse

logger = get_logger(__name__)
router = APIRouter(prefix="/investigation", tags=["investigation"])

_runner = StrandsInvestigationRunner()


@router.post(
    "/agent",
    response_model=Envelope[InvestigationAgentResponse],
    summary="Run AI log investigation agent",
    description=(
        "Interprets a troubleshooting question, plans read-only CloudWatch queries, "
        "executes bounded tool calls (logs, patterns, anomalies, metrics, deployments), "
        "and returns structured findings with proven facts vs hypotheses. "
        "Never executes remediation automatically."
    ),
)
async def run_investigation_agent(
    body: InvestigationAgentRequest,
    request: Request,
) -> Envelope[InvestigationAgentResponse]:
    if not settings.bedrock_configured and not settings.bedrock_use_mock_responses:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Bedrock is not configured and mock responses are disabled.",
        )

    logger.info(
        "investigation_agent question_chars=%d log_groups=%d mock=%s",
        len(body.question),
        len(body.log_group_names),
        settings.bedrock_use_mock_responses,
    )
    try:
        result = await _runner.investigate(body)
        return ok(result, request)
    except Exception as exc:
        logger.exception("Investigation agent failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
