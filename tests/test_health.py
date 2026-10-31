"""Health, readiness, settings, and liveness endpoints."""

import pytest


@pytest.mark.asyncio
async def test_liveness_endpoint(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "version" in data
    assert "X-Request-ID" in resp.headers


@pytest.mark.asyncio
async def test_health_endpoint_uses_envelope(client):
    resp = await client.get("/api/v1/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert body["error"] is None
    assert body["meta"]["request_id"]
    data = body["data"]
    assert data["status"] == "healthy"
    assert data["aws_mode"] == "mock"
    assert data["mock_aws"] is True
    assert data["bedrock_configured"] is False
    assert data["strands_configured"] is False
    assert data["ai_provider"] in {"bedrock", "strands"}
    assert "access_key" not in str(data).lower()
    assert "secret" not in str(data).lower()
    assert "account" not in str(data).lower()


@pytest.mark.asyncio
async def test_ready_endpoint(client):
    resp = await client.get("/api/v1/ready")
    assert resp.status_code == 200
    assert resp.json()["data"]["status"] == "ready"


@pytest.mark.asyncio
async def test_settings_omits_secrets(client):
    resp = await client.get("/api/v1/settings")
    assert resp.status_code == 200
    payload = str(resp.json()).lower()
    assert "aws_access_key" not in payload
    assert "aws_secret" not in payload
    assert "session_token" not in payload
    data = resp.json()["data"]
    assert data["aws_use_mock"] is True
    assert data["bedrock_enabled"] is False


@pytest.mark.asyncio
async def test_capabilities_are_skeleton(client):
    resp = await client.get("/api/v1/capabilities")
    assert resp.status_code == 200
    data = resp.json()["data"]
    for key in ("ingestion", "analytics", "correlation", "reasoning"):
        assert data[key]["status"] == "skeleton"
