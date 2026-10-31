"""Health, readiness, capabilities, and non-secret settings."""

from fastapi import APIRouter, Request

from app.core.responses import ok
from app.schemas.common import Envelope
from app.schemas.health import CapabilitiesData, HealthData, ReadyData, SettingsData
from app.services import health as health_service

router = APIRouter()


@router.get("/health", response_model=Envelope[HealthData])
async def health_check(request: Request) -> Envelope[HealthData]:
    return ok(await health_service.build_health(), request)


@router.get("/ready", response_model=Envelope[ReadyData])
async def readiness(request: Request) -> Envelope[ReadyData]:
    return ok(health_service.build_ready(), request)


@router.get("/capabilities", response_model=Envelope[CapabilitiesData])
async def capabilities(request: Request) -> Envelope[CapabilitiesData]:
    return ok(health_service.build_capabilities(), request)


@router.get("/settings", response_model=Envelope[SettingsData])
async def get_settings(request: Request) -> Envelope[SettingsData]:
    return ok(health_service.build_settings(), request)
