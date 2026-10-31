"""Tests for CloudWatch Logs discovery and query API endpoints."""

import pytest
from datetime import datetime, timedelta, UTC


@pytest.mark.asyncio
async def test_list_log_groups(client):
    """Test listing log groups returns mock data."""
    resp = await client.get("/api/v1/logs/groups")
    assert resp.status_code == 200

    body = resp.json()
    assert body["success"] is True
    data = body["data"]

    assert "log_groups" in data
    assert len(data["log_groups"]) > 0

    # Check first group has expected fields
    group = data["log_groups"][0]
    assert "log_group_name" in group
    assert group["log_group_name"].startswith("/aws/")
    assert "account_alias" in group
    assert "region" in group


@pytest.mark.asyncio
async def test_list_log_groups_with_prefix_filter(client):
    """Test filtering log groups by prefix."""
    resp = await client.get("/api/v1/logs/groups?prefix=/aws/ecs/")
    assert resp.status_code == 200

    body = resp.json()
    assert body["success"] is True
    data = body["data"]

    # All results should match the prefix
    for group in data["log_groups"]:
        assert group["log_group_name"].startswith("/aws/ecs/")


@pytest.mark.asyncio
async def test_list_log_groups_with_name_contains(client):
    """Test filtering log groups by name substring."""
    resp = await client.get("/api/v1/logs/groups?name_contains=prod")
    assert resp.status_code == 200

    body = resp.json()
    assert body["success"] is True
    data = body["data"]

    # All results should contain 'prod'
    for group in data["log_groups"]:
        assert "prod" in group["log_group_name"].lower()


@pytest.mark.asyncio
async def test_list_log_groups_pagination(client):
    """Test pagination of log groups."""
    # First page with limit
    resp = await client.get("/api/v1/logs/groups?limit=2")
    assert resp.status_code == 200

    body = resp.json()
    data = body["data"]

    assert len(data["log_groups"]) <= 2


@pytest.mark.asyncio
async def test_get_log_group_tags(client):
    """Test getting tags for a log group."""
    resp = await client.get("/api/v1/logs/groups/%2Faws%2Fecs%2Fprod-api/tags")
    assert resp.status_code == 200

    body = resp.json()
    assert body["success"] is True
    data = body["data"]

    # Should return a dict of tags
    assert isinstance(data, dict)


@pytest.mark.asyncio
async def test_start_query(client):
    """Test starting a Logs Insights query."""
    request_body = {
        "log_group_names": ["/aws/ecs/prod-api"],
        "query_string": "fields @timestamp, @message | sort @timestamp desc | limit 10",
        "time_range": {"preset": "1h"},
        "limit": 100,
    }

    resp = await client.post("/api/v1/logs/queries", json=request_body)
    assert resp.status_code == 200

    body = resp.json()
    assert body["success"] is True
    data = body["data"]

    assert "query_id" in data
    assert data["query_id"].startswith("mock-")
    assert data["status"] in ["Scheduled", "Running"]
    assert data["log_group_names"] == ["/aws/ecs/prod-api"]


@pytest.mark.asyncio
async def test_start_query_custom_time_range(client):
    """Test starting a query with custom time range."""
    now = datetime.now(UTC)
    start = now - timedelta(hours=2)

    request_body = {
        "log_group_names": ["/aws/ecs/prod-api"],
        "query_string": "fields @timestamp, @message | limit 10",
        "time_range": {
            "preset": "custom",
            "start_time": start.isoformat(),
            "end_time": now.isoformat(),
        },
    }

    resp = await client.post("/api/v1/logs/queries", json=request_body)
    assert resp.status_code == 200

    body = resp.json()
    assert body["success"] is True


@pytest.mark.asyncio
async def test_start_query_validation_empty_log_groups(client):
    """Test validation rejects empty log groups."""
    request_body = {
        "log_group_names": [],
        "query_string": "fields @timestamp, @message",
    }

    resp = await client.post("/api/v1/logs/queries", json=request_body)
    assert resp.status_code == 422  # Validation error


@pytest.mark.asyncio
async def test_start_query_validation_empty_query(client):
    """Test validation rejects empty query string."""
    request_body = {
        "log_group_names": ["/aws/ecs/prod-api"],
        "query_string": "",
    }

    resp = await client.post("/api/v1/logs/queries", json=request_body)
    assert resp.status_code == 422  # Validation error


@pytest.mark.asyncio
async def test_get_query_results(client):
    """Test getting query results."""
    # First start a query
    start_body = {
        "log_group_names": ["/aws/ecs/prod-api"],
        "query_string": "fields @timestamp, @message | limit 10",
    }
    start_resp = await client.post("/api/v1/logs/queries", json=start_body)
    query_id = start_resp.json()["data"]["query_id"]

    # Poll for results (mock completes after a few polls)
    for _ in range(5):
        resp = await client.get(f"/api/v1/logs/queries/{query_id}")
        assert resp.status_code == 200

        body = resp.json()
        assert body["success"] is True
        data = body["data"]

        assert data["query_id"] == query_id
        assert "status" in data
        assert "statistics" in data

        if data["status"] == "Complete":
            # Should have events
            assert "events" in data
            if data["events"]:
                event = data["events"][0]
                assert "timestamp" in event
                assert "message" in event
            break


@pytest.mark.asyncio
async def test_poll_query(client):
    """Test polling a query until completion."""
    # Start a query
    start_body = {
        "log_group_names": ["/aws/ecs/prod-api"],
        "query_string": "fields @timestamp, @message | limit 10",
    }
    start_resp = await client.post("/api/v1/logs/queries", json=start_body)
    query_id = start_resp.json()["data"]["query_id"]

    # Poll until complete (with short timeout for test)
    resp = await client.post(
        f"/api/v1/logs/queries/{query_id}/poll?timeout_seconds=30"
    )
    assert resp.status_code == 200

    body = resp.json()
    assert body["success"] is True
    data = body["data"]

    assert data["status"] == "Complete"
    assert "events" in data


@pytest.mark.asyncio
async def test_cancel_query(client):
    """Test cancelling a running query."""
    # Start a query
    start_body = {
        "log_group_names": ["/aws/ecs/prod-api"],
        "query_string": "fields @timestamp, @message | limit 10",
    }
    start_resp = await client.post("/api/v1/logs/queries", json=start_body)
    query_id = start_resp.json()["data"]["query_id"]

    # Cancel it
    resp = await client.delete(f"/api/v1/logs/queries/{query_id}")
    assert resp.status_code == 200

    body = resp.json()
    assert body["success"] is True
    data = body["data"]

    assert data["query_id"] == query_id
    assert "cancelled" in data


@pytest.mark.asyncio
async def test_list_active_queries(client):
    """Test listing active queries."""
    resp = await client.get("/api/v1/logs/queries")
    assert resp.status_code == 200

    body = resp.json()
    assert body["success"] is True
    data = body["data"]

    assert "queries" in data
    assert "total_count" in data
    assert isinstance(data["queries"], list)


@pytest.mark.asyncio
async def test_query_results_have_normalized_events(client):
    """Test that query results contain properly normalized events."""
    # Start and poll a query
    start_body = {
        "log_group_names": ["/aws/ecs/prod-api"],
        "query_string": "fields @timestamp, @message | limit 10",
    }
    start_resp = await client.post("/api/v1/logs/queries", json=start_body)
    query_id = start_resp.json()["data"]["query_id"]

    resp = await client.post(f"/api/v1/logs/queries/{query_id}/poll?timeout_seconds=30")
    data = resp.json()["data"]

    assert data["status"] == "Complete"

    # Check event structure if we have events
    if data["events"]:
        event = data["events"][0]

        # Required fields
        assert "timestamp" in event
        assert "message" in event
        assert "log_group" in event

        # Optional fields should be present even if null
        assert "log_stream" in event
        assert "account_alias" in event
        assert "region" in event
        assert "raw_fields" in event


@pytest.mark.asyncio
async def test_query_statistics_returned(client):
    """Test that query statistics are returned."""
    start_body = {
        "log_group_names": ["/aws/ecs/prod-api"],
        "query_string": "fields @timestamp, @message | limit 10",
    }
    start_resp = await client.post("/api/v1/logs/queries", json=start_body)
    query_id = start_resp.json()["data"]["query_id"]

    resp = await client.post(f"/api/v1/logs/queries/{query_id}/poll?timeout_seconds=30")
    data = resp.json()["data"]

    assert "statistics" in data
    stats = data["statistics"]

    assert "records_matched" in stats
    assert "records_scanned" in stats
    assert "bytes_scanned" in stats


@pytest.mark.asyncio
async def test_no_credentials_exposed(client):
    """Test that no AWS credentials are exposed in responses."""
    # Check log groups
    resp = await client.get("/api/v1/logs/groups")
    body_str = str(resp.json()).lower()

    assert "aws_access_key" not in body_str
    assert "aws_secret" not in body_str
    assert "session_token" not in body_str
    assert "akia" not in body_str  # AWS access key prefix

    # Check query results
    start_body = {
        "log_group_names": ["/aws/ecs/prod-api"],
        "query_string": "fields @timestamp, @message | limit 10",
    }
    start_resp = await client.post("/api/v1/logs/queries", json=start_body)
    query_id = start_resp.json()["data"]["query_id"]

    resp = await client.post(f"/api/v1/logs/queries/{query_id}/poll?timeout_seconds=30")
    body_str = str(resp.json()).lower()

    assert "aws_access_key" not in body_str
    assert "aws_secret" not in body_str
    assert "session_token" not in body_str
