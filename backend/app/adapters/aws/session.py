"""boto3 session factory using the default credential chain.

Never accept access keys from HTTP requests, query parameters, or the frontend.
"""

from __future__ import annotations

from typing import Any

import boto3

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


def build_session() -> Any:
    """Create a boto3 session from the default credential chain.

    Resolution order (boto3): environment variables, shared credential/config
    files, then container/instance/task IAM roles.
    """
    region = settings.resolved_aws_region
    logger.debug("Creating boto3 session region=%s", region or "default-chain")
    return boto3.Session(region_name=region)


def credentials_present() -> bool:
    """Return True when the default chain can resolve credentials. Never log secrets."""
    try:
        session = build_session()
        creds = session.get_credentials()
        return creds is not None
    except Exception:
        logger.debug("boto3 credential probe failed", exc_info=True)
        return False
