"""CloudWatch Logs discovery and query endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request

from app.adapters.aws.base import (
    AWSAccessDeniedError,
    AWSCredentialsError,
    AWSResourceNotFoundError,
    AWSThrottlingError,
    QueryConcurrencyError,
    QueryTimeoutError,
    ScanBudgetExceededError,
)
from app.core.responses import fail, ok
from app.schemas.common import Envelope
from app.schemas.logs import (
    ActiveQueriesResponse,
    CancelQueryResponse,
    LogGroupFilter,
    LogGroupListResponse,
    QueryResultsResponse,
    StartQueryRequest,
    StartQueryResponse,
)
from app.services.ingestion import LogIngestionService

router = APIRouter(prefix="/logs")


def _handle_aws_error(e: Exception, request: Request) -> HTTPException:
    """Convert AWS adapter exceptions to HTTP responses."""
    if isinstance(e, AWSThrottlingError):
        return HTTPException(
            status_code=429,
            detail=fail(
                "aws_throttling",
                f"AWS rate limit exceeded. Retry after {e.retry_after_seconds or 'a few'} seconds.",
                request,
            ).model_dump(mode="json"),
        )
    if isinstance(e, AWSCredentialsError):
        return HTTPException(
            status_code=401,
            detail=fail(
                "aws_credentials_error",
                "AWS credentials are invalid or expired. Contact your administrator.",
                request,
            ).model_dump(mode="json"),
        )
    if isinstance(e, AWSAccessDeniedError):
        return HTTPException(
            status_code=403,
            detail=fail(
                "aws_access_denied",
                "Access denied to AWS resource. Check IAM permissions.",
                request,
            ).model_dump(mode="json"),
        )
    if isinstance(e, AWSResourceNotFoundError):
        return HTTPException(
            status_code=404,
            detail=fail(
                "aws_resource_not_found",
                str(e),
                request,
            ).model_dump(mode="json"),
        )
    if isinstance(e, QueryConcurrencyError):
        return HTTPException(
            status_code=429,
            detail=fail(
                "query_concurrency_exceeded",
                str(e),
                request,
            ).model_dump(mode="json"),
        )
    if isinstance(e, QueryTimeoutError):
        return HTTPException(
            status_code=504,
            detail=fail(
                "query_timeout",
                str(e),
                request,
            ).model_dump(mode="json"),
        )
    if isinstance(e, ScanBudgetExceededError):
        return HTTPException(
            status_code=429,
            detail=fail(
                "scan_budget_exceeded",
                str(e),
                request,
            ).model_dump(mode="json"),
        )
    if isinstance(e, ValueError):
        return HTTPException(
            status_code=400,
            detail=fail(
                "invalid_request",
                str(e),
                request,
            ).model_dump(mode="json"),
        )
    # Unknown error
    raise


# -----------------------------------------------------------------------------
# Log Group Discovery
# -----------------------------------------------------------------------------


@router.get("/groups", response_model=Envelope[LogGroupListResponse])
async def list_log_groups(
    request: Request,
    prefix: Annotated[str | None, Query(max_length=512)] = None,
    account_alias: Annotated[str | None, Query(max_length=128)] = None,
    region: Annotated[str | None, Query(max_length=32)] = None,
    environment_tag: Annotated[str | None, Query(max_length=256)] = None,
    name_contains: Annotated[str | None, Query(max_length=256)] = None,
    next_token: Annotated[str | None, Query(max_length=1024)] = None,
    limit: Annotated[int, Query(ge=1, le=50)] = 50,
) -> Envelope[LogGroupListResponse]:
    """List CloudWatch log groups with optional filters.

    - **prefix**: Filter by log group name prefix (e.g., `/aws/ecs/`)
    - **account_alias**: Query only a specific configured account
    - **region**: Filter by AWS region
    - **environment_tag**: Filter by Environment tag value
    - **name_contains**: Filter by substring in log group name
    - **next_token**: Pagination token from previous response
    - **limit**: Maximum number of results (1-50)

    Returns log groups from the default account and any configured external accounts.
    """
    service = LogIngestionService()

    filter_params = LogGroupFilter(
        prefix=prefix,
        account_alias=account_alias,
        region=region,
        environment_tag=environment_tag,
        name_contains=name_contains,
    )

    try:
        result = await service.list_log_groups(
            filter_params=filter_params,
            next_token=next_token,
            limit=limit,
        )
        return ok(result, request)
    except Exception as e:
        raise _handle_aws_error(e, request) from e


@router.get("/groups/{log_group_name:path}/tags", response_model=Envelope[dict[str, str]])
async def get_log_group_tags(
    request: Request,
    log_group_name: str,
    account_alias: Annotated[str | None, Query(max_length=128)] = None,
) -> Envelope[dict[str, str]]:
    """Get tags for a specific log group.

    - **log_group_name**: Full log group name (e.g., `/aws/ecs/my-service`)
    - **account_alias**: Account containing the log group
    """
    service = LogIngestionService()

    try:
        tags = await service.get_log_group_tags(log_group_name, account_alias)
        return ok(tags, request)
    except Exception as e:
        raise _handle_aws_error(e, request) from e


# -----------------------------------------------------------------------------
# Query Management
# -----------------------------------------------------------------------------


@router.post("/queries", response_model=Envelope[StartQueryResponse])
async def start_query(
    request: Request,
    body: StartQueryRequest,
) -> Envelope[StartQueryResponse]:
    """Start a CloudWatch Logs Insights query.

    The query runs asynchronously. Use the returned `query_id` to poll for results.

    **Time range presets:**
    - `15m`: Last 15 minutes
    - `1h`: Last 1 hour (default)
    - `6h`: Last 6 hours
    - `24h`: Last 24 hours
    - `custom`: Use `start_time` and `end_time` fields

    **Example query strings:**
    - `fields @timestamp, @message | sort @timestamp desc | limit 100`
    - `filter @message like /ERROR/ | stats count() by bin(5m)`
    - `filter @message like /timeout/ | parse @message /(?<service>\\w+)-service/`

    **Limits:**
    - Maximum 50 log groups per query
    - Maximum 10,000 results per query
    - Query timeout: 60 seconds (configurable)
    """
    service = LogIngestionService()

    try:
        result = await service.start_query(body)
        return ok(result, request)
    except Exception as e:
        raise _handle_aws_error(e, request) from e


@router.get("/queries/{query_id}", response_model=Envelope[QueryResultsResponse])
async def get_query_results(
    request: Request,
    query_id: str,
    account_alias: Annotated[str | None, Query(max_length=128)] = None,
) -> Envelope[QueryResultsResponse]:
    """Get current status and results of a query.

    Poll this endpoint until `status` is one of:
    - `Complete`: Results are in `events` array
    - `Failed`: Check `error_message`
    - `Cancelled`: Query was cancelled

    **Status values:**
    - `Scheduled`: Query is queued
    - `Running`: Query is executing
    - `Complete`: Results available
    - `Failed`: Query failed
    - `Cancelled`: Query was cancelled
    """
    service = LogIngestionService()

    try:
        result = await service.get_query_results(query_id, account_alias)
        return ok(result, request)
    except Exception as e:
        raise _handle_aws_error(e, request) from e


@router.post("/queries/{query_id}/poll", response_model=Envelope[QueryResultsResponse])
async def poll_query(
    request: Request,
    query_id: str,
    account_alias: Annotated[str | None, Query(max_length=128)] = None,
    timeout_seconds: Annotated[int | None, Query(ge=5, le=300)] = None,
) -> Envelope[QueryResultsResponse]:
    """Poll a query until it completes or times out.

    This is a convenience endpoint that repeatedly polls the query status
    until it completes, fails, or the timeout is reached.

    - **query_id**: The query ID from start_query
    - **account_alias**: Account alias if using multi-account
    - **timeout_seconds**: Maximum time to wait (5-300 seconds)

    **Note:** This endpoint blocks until the query completes. For long-running
    queries, consider polling `/queries/{query_id}` yourself to show progress.
    """
    service = LogIngestionService()

    try:
        result = await service.poll_query_until_complete(
            query_id=query_id,
            account_alias=account_alias,
            timeout_seconds=timeout_seconds,
        )
        return ok(result, request)
    except Exception as e:
        raise _handle_aws_error(e, request) from e


@router.delete("/queries/{query_id}", response_model=Envelope[CancelQueryResponse])
async def cancel_query(
    request: Request,
    query_id: str,
    account_alias: Annotated[str | None, Query(max_length=128)] = None,
) -> Envelope[CancelQueryResponse]:
    """Cancel a running query.

    - **query_id**: The query ID to cancel
    - **account_alias**: Account alias if using multi-account

    Note: If the query has already completed, `cancelled` will be `false`.
    """
    service = LogIngestionService()

    try:
        result = await service.cancel_query(query_id, account_alias)
        return ok(result, request)
    except Exception as e:
        raise _handle_aws_error(e, request) from e


@router.get("/queries", response_model=Envelope[ActiveQueriesResponse])
async def list_active_queries(
    request: Request,
) -> Envelope[ActiveQueriesResponse]:
    """List currently active queries being tracked by this instance.

    Returns queries that were started through this API and are still running.
    Does not include queries started elsewhere or historical queries.
    """
    service = LogIngestionService()
    result = await service.get_active_queries()
    return ok(result, request)
