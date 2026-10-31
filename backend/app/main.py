"""FastAPI application factory."""

from __future__ import annotations

from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.logging import get_logger, setup_logging
from app.core.responses import fail
from app.schemas.health import LivenessResponse

logger = get_logger(__name__)


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    setup_logging()

    application = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @application.middleware("http")
    async def attach_request_id(request: Request, call_next):
        request_id = request.headers.get("X-Request-ID", str(uuid4()))
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    @application.get("/health", response_model=LivenessResponse, tags=["health"])
    async def liveness() -> LivenessResponse:
        """Load-balancer friendly liveness probe. Not wrapped in the API envelope."""
        return LivenessResponse(status="ok", version=settings.app_version)

    application.include_router(api_router)

    @application.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        logger.warning("Validation error on %s: %s", request.url.path, exc.errors())
        body = fail("validation_error", "Request validation failed", request)
        return JSONResponse(status_code=422, content=body.model_dump(mode="json"))

    @application.exception_handler(Exception)
    async def unhandled_error(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled error on %s: %s", request.url.path, exc)
        body = fail("internal_error", "An unexpected error occurred", request)
        return JSONResponse(status_code=500, content=body.model_dump(mode="json"))

    logger.info(
        "Application started name=%s version=%s aws_mode=%s",
        settings.app_name,
        settings.app_version,
        settings.aws_mode,
    )
    return application


app = create_app()
