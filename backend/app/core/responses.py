"""Standard JSON API envelope helpers."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from fastapi import Request

from app.schemas.common import APIError, Envelope, Meta


def _request_id(request: Request | None) -> str:
    if request is None:
        return str(uuid4())
    return getattr(request.state, "request_id", str(uuid4()))


def _meta(request: Request | None) -> Meta:
    return Meta(request_id=_request_id(request), timestamp=datetime.now(UTC))


def ok(data: Any, request: Request | None = None) -> Envelope[Any]:
    """Successful response envelope."""
    return Envelope(success=True, data=data, error=None, meta=_meta(request))


def fail(
    code: str,
    message: str,
    request: Request | None = None,
) -> Envelope[None]:
    """Error response envelope. Pair with an HTTP status code at the call site."""
    return Envelope(
        success=False,
        data=None,
        error=APIError(code=code, message=message),
        meta=_meta(request),
    )
