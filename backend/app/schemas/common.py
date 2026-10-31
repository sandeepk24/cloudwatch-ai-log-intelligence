"""Standard JSON API envelope."""

from datetime import datetime

from pydantic import BaseModel, Field


class Meta(BaseModel):
    request_id: str
    timestamp: datetime


class APIError(BaseModel):
    code: str
    message: str


class Envelope[T](BaseModel):
    success: bool
    data: T | None = None
    error: APIError | None = None
    meta: Meta = Field(...)
