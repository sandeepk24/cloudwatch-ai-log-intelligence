"""Live CloudWatch Logs adapter using boto3."""

from __future__ import annotations

import asyncio
from functools import partial
from typing import Any

from botocore.exceptions import ClientError, CredentialRetrievalError, NoCredentialsError

from app.adapters.aws.base import (
    AWSAccessDeniedError,
    AWSCredentialsError,
    AWSFeatureNotSupportedError,
    AWSResourceNotFoundError,
    AWSThrottlingError,
)
from app.adapters.aws.session import build_assumed_session, build_session
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# Throttling error codes from CloudWatch Logs
THROTTLING_ERROR_CODES = frozenset(
    {
        "Throttling",
        "ThrottlingException",
        "RequestThrottled",
        "TooManyRequestsException",
        "LimitExceededException",
        "ServiceUnavailableException",
    }
)

ACCESS_DENIED_ERROR_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
    }
)

# Error codes that indicate a feature (pattern command, anomaly detection
# APIs) is unavailable rather than a hard failure -- callers should fall
# back to local statistical computation instead of surfacing an error.
FEATURE_UNSUPPORTED_ERROR_CODES = frozenset(
    {
        "UnrecognizedClientException",
        "UnsupportedOperationException",
        "ValidationException",
        "MalformedQueryException",
    }
)


def _handle_client_error(error: ClientError, context: str) -> None:
    """Convert boto3 ClientError to domain exceptions."""
    code = error.response.get("Error", {}).get("Code", "Unknown")
    message = error.response.get("Error", {}).get("Message", str(error))

    if code in THROTTLING_ERROR_CODES:
        retry_after = error.response.get("ResponseMetadata", {}).get("RetryAfter")
        raise AWSThrottlingError(f"{context}: {message}", retry_after_seconds=retry_after)

    if code in ACCESS_DENIED_ERROR_CODES:
        raise AWSAccessDeniedError(f"{context}: {message}")

    if code == "ResourceNotFoundException":
        raise AWSResourceNotFoundError(f"{context}: {message}")

    if code in {"InvalidParameterException", "InvalidParameterValue"}:
        raise ValueError(f"{context}: {message}")

    # Re-raise for unknown errors
    raise


class BotoCloudWatchLogsAdapter:
    """CloudWatch Logs adapter using boto3 with support for multi-account access."""

    mode = "live"

    def __init__(
        self,
        account_alias: str | None = None,
        role_arn: str | None = None,
        external_id: str | None = None,
        region: str | None = None,
    ):
        """Initialize the adapter.

        Args:
            account_alias: Friendly name for the account (for display only)
            role_arn: IAM role ARN to assume for cross-account access
            external_id: External ID for assume role
            region: AWS region override
        """
        self.account_alias = account_alias
        self.region = region or settings.resolved_aws_region
        self._role_arn = role_arn
        self._external_id = external_id
        self._client: Any = None

    def _get_client(self) -> Any:
        """Get or create the CloudWatch Logs client."""
        if self._client is not None:
            return self._client

        try:
            if self._role_arn:
                session = build_assumed_session(
                    role_arn=self._role_arn,
                    external_id=self._external_id,
                    region=self.region,
                )
            else:
                session = build_session(region=self.region)

            self._client = session.client("logs")
            return self._client
        except (NoCredentialsError, CredentialRetrievalError) as e:
            raise AWSCredentialsError(f"Failed to obtain AWS credentials: {e}") from e

    async def _run_sync(self, func, *args, **kwargs) -> Any:
        """Run a synchronous boto3 call in the thread pool."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, partial(func, *args, **kwargs))

    async def describe_log_groups(
        self,
        prefix: str | None = None,
        next_token: str | None = None,
        limit: int = 50,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """List log groups with optional prefix filter and pagination."""
        client = self._get_client()

        params: dict[str, Any] = {"limit": min(limit, settings.cw_log_groups_page_size)}
        if prefix:
            params["logGroupNamePrefix"] = prefix
        if next_token:
            params["nextToken"] = next_token

        logger.debug(
            "describe_log_groups account=%s region=%s prefix=%s",
            self.account_alias,
            self.region,
            prefix,
        )

        try:
            response = await self._run_sync(client.describe_log_groups, **params)
            log_groups = response.get("logGroups", [])
            next_tok = response.get("nextToken")

            # Enrich with account info
            for group in log_groups:
                group["_account_alias"] = self.account_alias
                group["_region"] = self.region

            return log_groups, next_tok

        except ClientError as e:
            _handle_client_error(e, "describe_log_groups")
            raise

    async def list_tags_for_log_group(self, log_group_name: str) -> dict[str, str]:
        """Get tags for a specific log group."""
        client = self._get_client()

        logger.debug(
            "list_tags_for_log_group account=%s log_group=%s",
            self.account_alias,
            log_group_name,
        )

        try:
            response = await self._run_sync(
                client.list_tags_for_resource,
                resourceArn=log_group_name,
            )
            return response.get("tags", {})
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            # Older log groups may need list_tags_log_group
            if code == "InvalidParameterException":
                try:
                    response = await self._run_sync(
                        client.list_tags_log_group,
                        logGroupName=log_group_name,
                    )
                    return response.get("tags", {})
                except ClientError:
                    return {}
            _handle_client_error(e, f"list_tags_for_log_group({log_group_name})")
            raise

    async def start_insights_query(
        self,
        log_group_names: list[str],
        query_string: str,
        start_time: int,
        end_time: int,
        limit: int = 1000,
    ) -> str:
        """Start a CloudWatch Logs Insights query."""
        client = self._get_client()

        if len(log_group_names) > settings.cw_query_max_log_groups:
            raise ValueError(
                f"Too many log groups: {len(log_group_names)} > {settings.cw_query_max_log_groups}"
            )

        logger.info(
            "start_insights_query account=%s groups=%d query_chars=%d window=%d-%d",
            self.account_alias,
            len(log_group_names),
            len(query_string),
            start_time,
            end_time,
        )

        try:
            response = await self._run_sync(
                client.start_query,
                logGroupNames=log_group_names,
                startTime=start_time,
                endTime=end_time,
                queryString=query_string,
                limit=min(limit, 10000),
            )
            query_id = response["queryId"]
            logger.info(
                "Query started account=%s query_id=%s",
                self.account_alias,
                query_id,
            )
            return query_id

        except ClientError as e:
            _handle_client_error(e, "start_insights_query")
            raise

    async def get_query_results(self, query_id: str) -> dict[str, Any]:
        """Get results from a Logs Insights query."""
        client = self._get_client()

        logger.debug(
            "get_query_results account=%s query_id=%s",
            self.account_alias,
            query_id,
        )

        try:
            response = await self._run_sync(client.get_query_results, queryId=query_id)

            return {
                "queryId": query_id,
                "status": response.get("status", "Unknown"),
                "results": response.get("results", []),
                "statistics": response.get("statistics", {}),
                "encryptionKey": response.get("encryptionKey"),
            }

        except ClientError as e:
            _handle_client_error(e, f"get_query_results({query_id})")
            raise

    async def stop_query(self, query_id: str) -> bool:
        """Stop a running Logs Insights query."""
        client = self._get_client()

        logger.info(
            "stop_query account=%s query_id=%s",
            self.account_alias,
            query_id,
        )

        try:
            response = await self._run_sync(client.stop_query, queryId=query_id)
            success = response.get("success", False)
            logger.info("Query stopped query_id=%s success=%s", query_id, success)
            return success

        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            # Query may have already completed
            if code == "InvalidParameterException":
                logger.debug("Query already finished query_id=%s", query_id)
                return False
            _handle_client_error(e, f"stop_query({query_id})")
            raise

    async def describe_queries(
        self,
        log_group_name: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        """List running and recent queries."""
        client = self._get_client()

        params: dict[str, Any] = {}
        if log_group_name:
            params["logGroupName"] = log_group_name
        if status:
            params["status"] = status

        logger.debug(
            "describe_queries account=%s log_group=%s status=%s",
            self.account_alias,
            log_group_name,
            status,
        )

        try:
            response = await self._run_sync(client.describe_queries, **params)
            queries = response.get("queries", [])

            # Enrich with account info
            for query in queries:
                query["_account_alias"] = self.account_alias
                query["_region"] = self.region

            return queries

        except ClientError as e:
            _handle_client_error(e, "describe_queries")
            raise

    # -------------------------------------------------------------------
    # Optional native pattern analysis / anomaly detection
    # -------------------------------------------------------------------
    # These wrap CloudWatch Logs Insights' `pattern` query command and the
    # managed Log Anomaly Detection APIs. Both are treated as *optional*:
    # older botocore versions, some regions, or restrictive IAM policies may
    # not support them, in which case we raise AWSFeatureNotSupportedError
    # so callers (see app.services.pattern_analysis) can fall back to local
    # statistical computation rather than failing the whole request.

    async def start_pattern_query(
        self,
        log_group_names: list[str],
        start_time: int,
        end_time: int,
        message_filter: str | None = None,
        limit: int = 1000,
    ) -> str:
        """Start a CloudWatch Logs Insights query using the `pattern`
        command, which clusters matching log lines into shapes server-side.
        """
        query_string = "pattern @message"
        if message_filter:
            query_string = f"filter @message like /{message_filter}/ | {query_string}"

        try:
            return await self.start_insights_query(
                log_group_names=log_group_names,
                query_string=query_string,
                start_time=start_time,
                end_time=end_time,
                limit=limit,
            )
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in FEATURE_UNSUPPORTED_ERROR_CODES:
                raise AWSFeatureNotSupportedError(
                    f"Logs Insights `pattern` command is not supported/permitted here: {e}"
                ) from e
            raise

    async def list_log_anomaly_detectors(
        self,
        log_group_arn_list: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """List configured CloudWatch Log Anomaly Detectors.

        Raises AWSFeatureNotSupportedError if the account's botocore version
        predates this API, or if the call is otherwise unsupported/denied
        for reasons that indicate the *feature* (not just this call) is
        unavailable.
        """
        client = self._get_client()
        list_fn = getattr(client, "list_log_anomaly_detectors", None)
        if list_fn is None:
            raise AWSFeatureNotSupportedError(
                "This botocore version does not support list_log_anomaly_detectors."
            )

        params: dict[str, Any] = {}
        if log_group_arn_list:
            params["filterLogGroupArns"] = log_group_arn_list

        try:
            response = await self._run_sync(list_fn, **params)
            return response.get("anomalyDetectors", [])
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in FEATURE_UNSUPPORTED_ERROR_CODES:
                raise AWSFeatureNotSupportedError(
                    f"Log Anomaly Detection is not supported/permitted here: {e}"
                ) from e
            _handle_client_error(e, "list_log_anomaly_detectors")
            raise

    async def list_anomalies(
        self,
        anomaly_detector_arn: str,
        suppression_state: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """List anomalies reported by a configured Log Anomaly Detector."""
        client = self._get_client()
        list_fn = getattr(client, "list_anomalies", None)
        if list_fn is None:
            raise AWSFeatureNotSupportedError(
                "This botocore version does not support list_anomalies."
            )

        params: dict[str, Any] = {
            "anomalyDetectorArn": anomaly_detector_arn,
            "limit": limit,
        }
        if suppression_state:
            params["suppressionState"] = suppression_state

        try:
            response = await self._run_sync(list_fn, **params)
            return response.get("anomalies", [])
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in FEATURE_UNSUPPORTED_ERROR_CODES:
                raise AWSFeatureNotSupportedError(
                    f"Log Anomaly Detection is not supported/permitted here: {e}"
                ) from e
            _handle_client_error(e, "list_anomalies")
            raise
