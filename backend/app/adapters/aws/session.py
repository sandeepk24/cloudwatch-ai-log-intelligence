"""boto3 session factory using the default credential chain.

Never accept access keys from HTTP requests, query parameters, or the frontend.
"""

from __future__ import annotations

from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


def build_session(region: str | None = None) -> Any:
    """Create a boto3 session from the default credential chain.

    Resolution order (boto3): environment variables, shared credential/config
    files, then container/instance/task IAM roles.
    """
    effective_region = region or settings.resolved_aws_region
    logger.debug("Creating boto3 session region=%s", effective_region or "default-chain")
    return boto3.Session(region_name=effective_region)


def build_assumed_session(
    role_arn: str,
    external_id: str | None = None,
    region: str | None = None,
    session_name: str = "CloudWatchAILogIntelligence",
    duration_seconds: int = 3600,
) -> Any:
    """Create a boto3 session by assuming an IAM role.

    This is used for cross-account access where a read-only role has been
    configured in the target account and the trust policy allows this
    application's identity to assume it.

    Args:
        role_arn: The ARN of the role to assume
        external_id: Optional external ID for additional security
        region: AWS region for the session
        session_name: Name for the assumed role session
        duration_seconds: How long the credentials should be valid

    Returns:
        A boto3 Session with the assumed role credentials

    Raises:
        AWSCredentialsError: If the role cannot be assumed
    """
    from app.adapters.aws.base import AWSAccessDeniedError, AWSCredentialsError

    logger.info(
        "Assuming role role_arn=%s external_id=%s region=%s",
        role_arn,
        "***" if external_id else None,
        region,
    )

    try:
        # Use the default session to assume the role
        base_session = build_session(region=region)
        sts = base_session.client("sts")

        assume_params = {
            "RoleArn": role_arn,
            "RoleSessionName": session_name,
            "DurationSeconds": duration_seconds,
        }

        if external_id:
            assume_params["ExternalId"] = external_id

        response = sts.assume_role(**assume_params)
        credentials = response["Credentials"]

        # Create a new session with the temporary credentials
        assumed_session = boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=region or settings.resolved_aws_region,
        )

        logger.info(
            "Role assumed successfully role_arn=%s expires=%s",
            role_arn,
            credentials["Expiration"],
        )

        return assumed_session

    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        message = e.response.get("Error", {}).get("Message", str(e))

        if code in {"AccessDenied", "AccessDeniedException"}:
            raise AWSAccessDeniedError(
                f"Cannot assume role {role_arn}: {message}",
                resource=role_arn,
            ) from e

        raise AWSCredentialsError(f"Failed to assume role {role_arn}: {message}") from e

    except NoCredentialsError as e:
        raise AWSCredentialsError(f"No base credentials available to assume role {role_arn}") from e


def credentials_present() -> bool:
    """Return True when the default chain can resolve credentials. Never log secrets."""
    try:
        session = build_session()
        creds = session.get_credentials()
        return creds is not None
    except Exception:
        logger.debug("boto3 credential probe failed", exc_info=True)
        return False


def get_caller_identity() -> dict[str, str] | None:
    """Get the current caller identity. Returns None if credentials are invalid."""
    try:
        session = build_session()
        sts = session.client("sts")
        return sts.get_caller_identity()
    except Exception:
        logger.debug("get_caller_identity failed", exc_info=True)
        return None
