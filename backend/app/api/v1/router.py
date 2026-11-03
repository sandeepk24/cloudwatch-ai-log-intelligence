"""API v1 router."""

from fastapi import APIRouter

from app.api.v1 import health, incidents, intelligence, investigation, logs

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router, tags=["health"])
api_router.include_router(logs.router, tags=["logs"])
api_router.include_router(intelligence.router, tags=["intelligence"])
api_router.include_router(incidents.router, tags=["incidents"])
api_router.include_router(investigation.router)
