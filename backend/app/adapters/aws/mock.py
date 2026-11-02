"""Canned CloudWatch responses for local development. No AWS calls."""

from __future__ import annotations

import random
import string
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from app.adapters.aws.base import AWSFeatureNotSupportedError
from app.core.logging import get_logger
from app.schemas.logs import QueryStatus

logger = get_logger(__name__)


def _generate_query_id() -> str:
    """Generate a mock query ID."""
    chars = string.ascii_lowercase + string.digits
    suffix = "".join(random.choice(chars) for _ in range(8))
    return f"mock-{suffix}"


def _generate_event_id() -> str:
    """Generate a mock event ID."""
    return f"evt-{''.join(random.choice(string.hexdigits.lower()) for _ in range(32))}"


# Mock log groups representing different AWS services
MOCK_LOG_GROUPS: list[dict[str, Any]] = [
    {
        "logGroupName": "/aws/ecs/prod-api",
        "arn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/ecs/prod-api",
        "storedBytes": 1_048_576_000,
        "retentionInDays": 14,
        "creationTime": int((datetime.now(UTC) - timedelta(days=90)).timestamp() * 1000),
        "_tags": {"Environment": "production", "Service": "api", "Team": "platform"},
    },
    {
        "logGroupName": "/aws/ecs/prod-worker",
        "arn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/ecs/prod-worker",
        "storedBytes": 524_288_000,
        "retentionInDays": 14,
        "creationTime": int((datetime.now(UTC) - timedelta(days=60)).timestamp() * 1000),
        "_tags": {"Environment": "production", "Service": "worker", "Team": "platform"},
    },
    {
        "logGroupName": "/aws/ecs/staging-api",
        "arn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/ecs/staging-api",
        "storedBytes": 262_144_000,
        "retentionInDays": 7,
        "creationTime": int((datetime.now(UTC) - timedelta(days=30)).timestamp() * 1000),
        "_tags": {"Environment": "staging", "Service": "api", "Team": "platform"},
    },
    {
        "logGroupName": "/aws/lambda/payment-processor",
        "arn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/payment-processor",
        "storedBytes": 128_000_000,
        "retentionInDays": 30,
        "creationTime": int((datetime.now(UTC) - timedelta(days=180)).timestamp() * 1000),
        "_tags": {"Environment": "production", "Service": "payments", "Team": "fintech"},
    },
    {
        "logGroupName": "/aws/lambda/notification-sender",
        "arn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/notification-sender",
        "storedBytes": 64_000_000,
        "retentionInDays": 7,
        "creationTime": int((datetime.now(UTC) - timedelta(days=120)).timestamp() * 1000),
        "_tags": {"Environment": "production", "Service": "notifications", "Team": "messaging"},
    },
    {
        "logGroupName": "/aws/apigateway/main-api",
        "arn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/apigateway/main-api",
        "storedBytes": 2_048_000_000,
        "retentionInDays": 30,
        "creationTime": int((datetime.now(UTC) - timedelta(days=365)).timestamp() * 1000),
        "_tags": {"Environment": "production", "Service": "gateway", "Team": "platform"},
    },
    {
        "logGroupName": "/aws/rds/cluster-main/error",
        "arn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/rds/cluster-main/error",
        "storedBytes": 32_000_000,
        "retentionInDays": 90,
        "creationTime": int((datetime.now(UTC) - timedelta(days=400)).timestamp() * 1000),
        "_tags": {"Environment": "production", "Service": "database", "Team": "data"},
    },
    {
        "logGroupName": "/aws/elasticbeanstalk/dev-app/var/log/web.stdout.log",
        "arn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/elasticbeanstalk/dev-app",
        "storedBytes": 16_000_000,
        "retentionInDays": 3,
        "creationTime": int((datetime.now(UTC) - timedelta(days=15)).timestamp() * 1000),
        "_tags": {"Environment": "development", "Service": "legacy-app", "Team": "legacy"},
    },
]

# Sample error and warning messages for mock events
MOCK_MESSAGES = [
    ("ERROR", "payment-service timeout talking to downstream payment gateway after 30000ms"),
    ("ERROR", "Database connection pool exhausted: max_connections=100 active=100 waiting=47"),
    ("ERROR", "OutOfMemoryError: Java heap space in worker thread pool-3-thread-7"),
    ("ERROR", "SocketTimeoutException: Read timed out connecting to redis-cluster.internal:6379"),
    ("WARN", "Retrying GetItem after ProvisionedThroughputExceeded (attempt 2/3)"),
    ("WARN", "Circuit breaker OPEN for service=user-profile-service failures=15 threshold=10"),
    ("WARN", "Request latency exceeded SLO: path=/api/v1/orders latency_ms=2847 slo_ms=1000"),
    ("WARN", "Memory usage high: heap_used=1.8GB heap_max=2GB gc_overhead=23%"),
    ("INFO", "Health check passed: status=healthy uptime=3d14h22m services=all_green"),
    ("INFO", "Deployment started: version=v2.34.1 environment=production replicas=3"),
    ("INFO", "Batch job completed: processed=45782 failed=12 duration=847s"),
    ("DEBUG", "Cache hit for key=user:12345:preferences ttl=3600s"),
]

MOCK_LOG_STREAMS = [
    "ecs/prod-api/i-0abc123def456789a",
    "ecs/prod-api/i-0def456789abc1230b",
    "ecs/prod-worker/i-0789abc123def4560c",
    "lambda/payment-processor/2026/10/30/[$LATEST]abc123",
    "lambda/notification-sender/2026/10/30/[$LATEST]def456",
]


class MockQueryState:
    """Track state of mock queries for realistic polling simulation."""

    def __init__(self):
        self._queries: dict[str, dict[str, Any]] = {}

    def start_query(
        self,
        query_id: str,
        log_group_names: list[str],
        query_string: str,
        start_time: int,
        end_time: int,
    ) -> None:
        """Register a new mock query."""
        self._queries[query_id] = {
            "query_id": query_id,
            "log_group_names": log_group_names,
            "query_string": query_string,
            "start_time": start_time,
            "end_time": end_time,
            "created_at": time.time(),
            "status": QueryStatus.RUNNING.value,
            "poll_count": 0,
            "is_pattern": "pattern @message" in query_string,
        }

    def get_results(self, query_id: str) -> dict[str, Any]:
        """Get mock results, simulating query completion after a few polls."""
        if query_id not in self._queries:
            # Return completed for unknown queries (might be from a previous session)
            return self._generate_results(query_id, QueryStatus.COMPLETE.value)

        query = self._queries[query_id]
        query["poll_count"] += 1

        # Simulate query running for 2-3 polls before completing
        if query["poll_count"] < random.randint(2, 3):
            return {
                "queryId": query_id,
                "status": QueryStatus.RUNNING.value,
                "results": [],
                "statistics": {"recordsMatched": 0, "recordsScanned": 0, "bytesScanned": 0},
            }

        # Mark as complete and return results
        query["status"] = QueryStatus.COMPLETE.value
        if query.get("is_pattern"):
            return self._generate_pattern_results(query_id, QueryStatus.COMPLETE.value)
        return self._generate_results(query_id, QueryStatus.COMPLETE.value)

    def stop_query(self, query_id: str) -> bool:
        """Stop a mock query."""
        if query_id in self._queries:
            self._queries[query_id]["status"] = QueryStatus.CANCELLED.value
            return True
        return False

    def get_queries(self, status: str | None = None) -> list[dict[str, Any]]:
        """Get list of queries with optional status filter."""
        queries = []
        for qid, q in self._queries.items():
            if status and q["status"] != status:
                continue
            queries.append(
                {
                    "queryId": qid,
                    "logGroupName": q["log_group_names"][0] if q["log_group_names"] else None,
                    "status": q["status"],
                    "createTime": int(q["created_at"] * 1000),
                }
            )
        return queries

    def _generate_results(self, query_id: str, status: str) -> dict[str, Any]:
        """Generate mock query results."""
        now = datetime.now(UTC)
        events = []

        # Generate 5-15 mock events
        num_events = random.randint(5, 15)
        for _ in range(num_events):
            ts = now - timedelta(minutes=random.randint(1, 60))
            level, message = random.choice(MOCK_MESSAGES)
            stream = random.choice(MOCK_LOG_STREAMS)

            events.append(
                [
                    {"field": "@timestamp", "value": ts.isoformat()},
                    {"field": "@message", "value": f"{level} {message}"},
                    {"field": "@logStream", "value": stream},
                    {"field": "@ptr", "value": f"mock-ptr-{_generate_event_id()}"},
                ]
            )

        return {
            "queryId": query_id,
            "status": status,
            "results": events,
            "statistics": {
                "recordsMatched": float(len(events)),
                "recordsScanned": float(len(events) * random.randint(10, 100)),
                "bytesScanned": float(len(events) * random.randint(1000, 10000)),
            },
        }

    def _generate_pattern_results(self, query_id: str, status: str) -> dict[str, Any]:
        """Generate mock results approximating a CloudWatch Logs Insights
        `pattern` command: one row per clustered pattern with a sample
        count and severity label, rather than one row per raw event.

        This is a local approximation for development only; it is not a
        faithful reproduction of CloudWatch's pattern-clustering algorithm.
        """
        rows = []
        for level, message in MOCK_MESSAGES:
            sample_count = random.randint(3, 60)
            rows.append(
                [
                    {"field": "@pattern", "value": message.split(":")[0][:60]},
                    {"field": "@sampleCount", "value": str(sample_count)},
                    {"field": "@severityLabel", "value": level},
                    {"field": "@logSamples", "value": f"{level} {message}"},
                ]
            )

        return {
            "queryId": query_id,
            "status": status,
            "results": rows,
            "statistics": {
                "recordsMatched": float(len(rows)),
                "recordsScanned": float(len(rows) * random.randint(50, 200)),
                "bytesScanned": float(len(rows) * random.randint(2000, 20000)),
            },
        }


# Global mock query state
_mock_query_state = MockQueryState()


class MockCloudWatchLogsAdapter:
    """Mock CloudWatch Logs adapter for local development."""

    mode = "mock"
    account_alias: str | None = "mock-account"
    region: str | None = "us-east-1"

    def __init__(
        self,
        account_alias: str | None = None,
        region: str | None = None,
    ):
        self.account_alias = account_alias or "mock-account"
        self.region = region or "us-east-1"

    async def describe_log_groups(
        self,
        prefix: str | None = None,
        next_token: str | None = None,
        limit: int = 50,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Return mock log groups with pagination."""
        logger.debug(
            "Mock describe_log_groups prefix=%s next_token=%s limit=%s",
            prefix,
            next_token,
            limit,
        )

        # Filter by prefix
        groups = MOCK_LOG_GROUPS
        if prefix:
            groups = [g for g in groups if g["logGroupName"].startswith(prefix)]

        # Handle pagination
        start_idx = 0
        if next_token:
            try:
                start_idx = int(next_token)
            except ValueError:
                start_idx = 0

        end_idx = min(start_idx + limit, len(groups))
        page = groups[start_idx:end_idx]

        # Enrich with account info
        for group in page:
            group["_account_alias"] = self.account_alias
            group["_region"] = self.region

        # Generate next token if there are more results
        new_next_token = str(end_idx) if end_idx < len(groups) else None

        return page, new_next_token

    async def list_tags_for_log_group(self, log_group_name: str) -> dict[str, str]:
        """Return mock tags for a log group."""
        logger.debug("Mock list_tags_for_log_group log_group=%s", log_group_name)

        for group in MOCK_LOG_GROUPS:
            if group["logGroupName"] == log_group_name:
                return group.get("_tags", {})

        return {}

    async def start_insights_query(
        self,
        log_group_names: list[str],
        query_string: str,
        start_time: int,
        end_time: int,
        limit: int = 1000,
    ) -> str:
        """Start a mock Logs Insights query."""
        query_id = _generate_query_id()
        logger.info(
            "Mock start_insights_query query_id=%s groups=%s query_chars=%d",
            query_id,
            log_group_names,
            len(query_string),
        )

        _mock_query_state.start_query(
            query_id=query_id,
            log_group_names=log_group_names,
            query_string=query_string,
            start_time=start_time,
            end_time=end_time,
        )

        return query_id

    async def get_query_results(self, query_id: str) -> dict[str, Any]:
        """Get mock query results with simulated polling behavior."""
        logger.debug("Mock get_query_results query_id=%s", query_id)
        return _mock_query_state.get_results(query_id)

    async def stop_query(self, query_id: str) -> bool:
        """Stop a mock query."""
        logger.info("Mock stop_query query_id=%s", query_id)
        return _mock_query_state.stop_query(query_id)

    async def describe_queries(
        self,
        log_group_name: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        """List mock queries."""
        logger.debug(
            "Mock describe_queries log_group=%s status=%s",
            log_group_name,
            status,
        )
        queries = _mock_query_state.get_queries(status=status)

        # Enrich with account info
        for query in queries:
            query["_account_alias"] = self.account_alias
            query["_region"] = self.region

        return queries

    async def start_pattern_query(
        self,
        log_group_names: list[str],
        start_time: int,
        end_time: int,
        message_filter: str | None = None,
        limit: int = 1000,
    ) -> str:
        """Mock equivalent of the Logs Insights `pattern` command."""
        query_string = "pattern @message"
        if message_filter:
            query_string = f"filter @message like /{message_filter}/ | {query_string}"
        return await self.start_insights_query(
            log_group_names=log_group_names,
            query_string=query_string,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
        )

    async def list_log_anomaly_detectors(
        self,
        log_group_arn_list: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Mock mode has no managed anomaly detector configured by default,
        matching the common real-world case where this optional feature has
        not been opted into for an account."""
        logger.debug("Mock list_log_anomaly_detectors (none configured)")
        return []

    async def list_anomalies(
        self,
        anomaly_detector_arn: str,
        suppression_state: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """No detector is configured in mock mode, so this always reports
        the feature as unsupported -- exercising the same fallback path a
        live account without an anomaly detector would take."""
        raise AWSFeatureNotSupportedError(
            "No Log Anomaly Detector is configured in mock mode."
        )


class MockCloudWatchMetricsAdapter:
    """Mock CloudWatch Metrics adapter for local development."""

    mode = "mock"

    async def list_metrics(
        self,
        namespace: str | None = None,
        metric_name: str | None = None,
    ) -> list[dict[str, Any]]:
        logger.debug("Mock list_metrics namespace=%s metric=%s", namespace, metric_name)
        return [
            {
                "namespace": namespace or "AWS/ECS",
                "metricName": metric_name or "CPUUtilization",
                "dimensions": [{"Name": "ServiceName", "Value": "sample-api"}],
            }
        ]

    async def get_metric_data(self, metric_name: str, namespace: str) -> dict[str, Any]:
        logger.debug("Mock get_metric_data %s/%s", namespace, metric_name)
        return {
            "namespace": namespace,
            "metricName": metric_name,
            "values": [12.0, 18.5, 41.0, 87.2, 65.3, 42.1],
            "timestamps": [
                (datetime.now(UTC) - timedelta(minutes=i * 5)).isoformat() for i in range(6)
            ],
            "status": "Complete",
        }
