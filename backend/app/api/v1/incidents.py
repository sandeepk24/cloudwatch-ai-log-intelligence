"""Incident Correlation Engine API endpoints.

POST /api/v1/incidents/analyze
    Run the full cross-service correlation pipeline over provided signals.

POST /api/v1/incidents/scenario
    Generate a synthetic failure scenario (signals only; no analysis).

GET  /api/v1/incidents/scenarios
    List available synthetic scenarios.

POST /api/v1/incidents/scenario/{name}/analyze
    Generate a synthetic scenario AND run analysis in one call — useful
    for quick demos and integration tests.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from app.core.logging import get_logger
from app.core.responses import fail, ok
from app.schemas.common import Envelope
from app.schemas.incidents import (
    AnalyzeIncidentRequest,
    AnalyzeIncidentResponse,
    SyntheticScenarioRequest,
    SyntheticScenarioResponse,
)
from app.correlation.engine import CorrelationEngine
from app.scenarios.synthetic import ScenarioGenerator

logger = get_logger(__name__)
router = APIRouter(prefix="/incidents")

_engine = CorrelationEngine()
_scenario_gen = ScenarioGenerator()


@router.post(
    "/analyze",
    response_model=Envelope[AnalyzeIncidentResponse],
    summary="Run cross-service incident correlation",
    description=(
        "Accepts a list of normalized signals from ECS, EKS, EC2, Lambda, ALB, RDS, "
        "and CloudWatch Alarms. Returns a full IncidentReport with timeline, "
        "affected services, deployment analysis, infrastructure symptoms, "
        "and ranked root-cause hypotheses with explicit evidence provenance."
    ),
)
async def analyze_incident(
    body: AnalyzeIncidentRequest,
    request: Request,
) -> Envelope[AnalyzeIncidentResponse]:
    logger.info(
        "analyze_incident signal_count=%d window_minutes=%d",
        len(body.signals),
        body.incident_window_minutes,
    )
    try:
        report = _engine.analyze(body.signals, body)
        return ok(AnalyzeIncidentResponse(report=report), request)
    except Exception as exc:
        logger.exception("analyze_incident failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/scenario",
    response_model=Envelope[SyntheticScenarioResponse],
    summary="Generate a synthetic failure scenario",
    description=(
        "Returns a list of synthetic signals for the named scenario. "
        "Use this to test the correlation engine with known failure patterns."
    ),
)
async def generate_scenario(
    body: SyntheticScenarioRequest,
    request: Request,
) -> Envelope[SyntheticScenarioResponse]:
    logger.info("generate_scenario name=%s seed=%s", body.scenario_name, body.seed)
    try:
        result = _scenario_gen.generate(body.scenario_name, seed=body.seed)
        return ok(SyntheticScenarioResponse(**result), request)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("generate_scenario failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/scenarios",
    summary="List available synthetic scenarios",
)
async def list_scenarios(request: Request):
    scenarios = _scenario_gen.list_scenarios()
    return ok({"scenarios": scenarios}, request)


@router.post(
    "/scenario/{scenario_name}/analyze",
    response_model=Envelope[AnalyzeIncidentResponse],
    summary="Generate scenario and run correlation in one call",
    description=(
        "Convenience endpoint: generates signals for the named scenario, "
        "then runs the full correlation pipeline. Accepts optional overrides "
        "for incident_window_minutes, deployment_lookback_minutes, etc."
    ),
)
async def scenario_analyze(
    scenario_name: str,
    request: Request,
    seed: int | None = None,
    incident_window_minutes: int = 60,
    deployment_lookback_minutes: int = 30,
    deployment_after_minutes: int = 30,
    max_hypotheses: int = 5,
) -> Envelope[AnalyzeIncidentResponse]:
    logger.info(
        "scenario_analyze name=%s seed=%s window=%d",
        scenario_name,
        seed,
        incident_window_minutes,
    )
    try:
        scenario = _scenario_gen.generate(scenario_name, seed=seed)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    analyze_request = AnalyzeIncidentRequest(
        signals=scenario["signals"],
        incident_window_minutes=incident_window_minutes,
        deployment_lookback_minutes=deployment_lookback_minutes,
        deployment_after_minutes=deployment_after_minutes,
        max_hypotheses=max_hypotheses,
    )
    try:
        report = _engine.analyze(scenario["signals"], analyze_request)
        return ok(AnalyzeIncidentResponse(report=report), request)
    except Exception as exc:
        logger.exception("scenario_analyze failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
