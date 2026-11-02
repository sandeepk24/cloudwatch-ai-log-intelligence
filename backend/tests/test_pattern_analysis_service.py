"""Deterministic service- and API-level tests for CloudWatch pattern/anomaly
analysis.

`PatternAnalysisService.fetch_classified_events` is the only method that
talks to AWS (via `LogIngestionService`). Every test here monkeypatches it
with a fixed, synthetic dataset so results are fully reproducible and do
not depend on the randomized mock AWS adapter or wall-clock time.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.schemas.analytics import AnalysisStatus
from app.schemas.logs import TimeRangePreset
from app.services.pattern_analysis import PatternAnalysisService

BASE = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)


def _ev(minute: float, message: str, severity: str = "INFO") -> dict:
    return {
        "timestamp": BASE + timedelta(minutes=minute),
        "message": message,
        "severity": severity,
        "log_group": "/aws/test",
        "ptr": None,
    }


@pytest.fixture
def service() -> PatternAnalysisService:
    return PatternAnalysisService()


# =============================================================================
# get_patterns
# =============================================================================


class TestGetPatternsService:
    @pytest.mark.asyncio
    async def test_new_pattern_detected_against_baseline(self, service, monkeypatch):
        # Window: current = [BASE+60, BASE+120), baseline = [BASE, BASE+60)
        baseline_events = [_ev(i, "INFO steady state", "INFO") for i in range(10)]
        current_events = [_ev(60 + i, "INFO steady state", "INFO") for i in range(10)] + [
            _ev(61, "ERROR brand new failure mode", "ERROR")
        ]

        async def fake_fetch(log_group_names, start_time, end_time, account_alias=None, query_string=None):
            if start_time == BASE:
                return baseline_events
            return current_events

        monkeypatch.setattr(service, "fetch_classified_events", fake_fetch)

        result = await service.get_patterns(
            log_group_names=["/aws/test"],
            time_range_preset=TimeRangePreset.CUSTOM,
            start_time=BASE + timedelta(minutes=60),
            end_time=BASE + timedelta(minutes=120),
            baseline_periods=1,
        )

        assert result.status == AnalysisStatus.OK
        assert result.total_events == len(current_events)
        assert result.diff is not None
        new_messages = {p.representative_message for p in result.diff.new_patterns}
        assert "ERROR brand new failure mode" in new_messages
        new_pattern = next(p for p in result.diff.new_patterns if p.representative_message == "ERROR brand new failure mode")
        assert new_pattern.is_new is True
        assert new_pattern.severity_score > 0

    @pytest.mark.asyncio
    async def test_baseline_periods_zero_skips_diff(self, service, monkeypatch):
        async def fake_fetch(log_group_names, start_time, end_time, account_alias=None, query_string=None):
            return [_ev(0, "INFO hello", "INFO")]

        monkeypatch.setattr(service, "fetch_classified_events", fake_fetch)

        result = await service.get_patterns(
            log_group_names=["/aws/test"],
            time_range_preset=TimeRangePreset.CUSTOM,
            start_time=BASE,
            end_time=BASE + timedelta(minutes=10),
            baseline_periods=0,
        )
        assert result.status == AnalysisStatus.PARTIAL
        assert result.diff is None
        assert any("baseline_periods=0" in n for n in result.notes)

    @pytest.mark.asyncio
    async def test_empty_baseline_is_insufficient_data_not_all_new(self, service, monkeypatch):
        current_events = [_ev(60, "ERROR something", "ERROR")]

        async def fake_fetch(log_group_names, start_time, end_time, account_alias=None, query_string=None):
            if start_time == BASE:
                return []  # baseline window had zero events
            return current_events

        monkeypatch.setattr(service, "fetch_classified_events", fake_fetch)

        result = await service.get_patterns(
            log_group_names=["/aws/test"],
            time_range_preset=TimeRangePreset.CUSTOM,
            start_time=BASE + timedelta(minutes=60),
            end_time=BASE + timedelta(minutes=120),
            baseline_periods=1,
        )
        assert result.status == AnalysisStatus.INSUFFICIENT_DATA
        # Explicitly no diff -- we must not claim "all current patterns are new"
        # just because the baseline fetch came back empty.
        assert result.diff is None
        assert len(result.patterns) == 1

    @pytest.mark.asyncio
    async def test_no_events_at_all(self, service, monkeypatch):
        async def fake_fetch(log_group_names, start_time, end_time, account_alias=None, query_string=None):
            return []

        monkeypatch.setattr(service, "fetch_classified_events", fake_fetch)

        result = await service.get_patterns(
            log_group_names=["/aws/test"],
            time_range_preset=TimeRangePreset.CUSTOM,
            start_time=BASE,
            end_time=BASE + timedelta(minutes=10),
            baseline_periods=1,
        )
        assert result.total_events == 0
        assert result.patterns == []


# =============================================================================
# get_anomalies
# =============================================================================


class TestGetAnomaliesService:
    @pytest.mark.asyncio
    async def test_insufficient_history_when_history_periods_zero(self, service, monkeypatch):
        async def fake_fetch(log_group_names, start_time, end_time, account_alias=None, query_string=None):
            return [_ev(0, "ERROR boom", "ERROR")]

        monkeypatch.setattr(service, "fetch_classified_events", fake_fetch)

        result = await service.get_anomalies(
            log_group_names=["/aws/test"],
            time_range_preset=TimeRangePreset.CUSTOM,
            start_time=BASE,
            end_time=BASE + timedelta(minutes=10),
            history_periods=0,
        )
        assert result.status == AnalysisStatus.INSUFFICIENT_DATA
        assert result.frequency_anomalies == []
        assert any("historical bucket" in n for n in result.notes)

    @pytest.mark.asyncio
    async def test_frequency_spike_surfaced_in_current_window(self, service, monkeypatch):
        # 5-minute buckets. Baseline history has mild variance (2-3
        # events/bucket); the current window has one 5-minute bucket with a
        # clear spike (40 events).
        events = []
        # history window: [-25, 0) minutes, 5 buckets of 5 min each
        pattern = [2, 3, 2, 3, 2]
        for bucket_idx, count in enumerate(pattern):
            bucket_start = -25 + bucket_idx * 5
            for i in range(count):
                events.append(_ev(bucket_start + i * 0.5, f"INFO baseline {bucket_idx}-{i}", "INFO"))
        # current window: [0, 5) minutes -- spike
        for i in range(40):
            events.append(_ev(i * 0.1, f"ERROR spike {i}", "ERROR"))

        async def fake_fetch(log_group_names, start_time, end_time, account_alias=None, query_string=None):
            return events

        monkeypatch.setattr(service, "fetch_classified_events", fake_fetch)

        result = await service.get_anomalies(
            log_group_names=["/aws/test"],
            time_range_preset=TimeRangePreset.CUSTOM,
            start_time=BASE,
            end_time=BASE + timedelta(minutes=5),
            bucket_minutes=5,
            history_periods=5,
        )
        assert result.status == AnalysisStatus.OK
        assert len(result.frequency_anomalies) == 1
        assert result.frequency_anomalies[0].classification.value in ("anomaly", "incident")

    @pytest.mark.asyncio
    async def test_resource_signal_included_when_metric_requested(self, service, monkeypatch):
        async def fake_fetch(log_group_names, start_time, end_time, account_alias=None, query_string=None):
            return []

        async def fake_get_metric_data(metric_name, namespace):
            return {"namespace": namespace, "metricName": metric_name, "values": [1.0]}  # too few points

        class _StubMetrics:
            mode = "mock"

            async def list_metrics(self, namespace=None, metric_name=None):
                return []

            async def get_metric_data(self, metric_name, namespace):
                return await fake_get_metric_data(metric_name, namespace)

        monkeypatch.setattr(service, "fetch_classified_events", fake_fetch)
        monkeypatch.setattr(
            "app.services.pattern_analysis.get_metrics_adapter", lambda: _StubMetrics()
        )

        result = await service.get_anomalies(
            log_group_names=["/aws/test"],
            time_range_preset=TimeRangePreset.CUSTOM,
            start_time=BASE,
            end_time=BASE + timedelta(minutes=10),
            history_periods=1,
            metric_namespace="AWS/ECS",
            metric_name="CPUUtilization",
        )
        assert len(result.resource_signals) == 1
        assert result.resource_signals[0].status == AnalysisStatus.INSUFFICIENT_DATA
        # A metrics signal problem should not escalate an otherwise-OK log
        # analysis past PARTIAL.
        assert result.status in (AnalysisStatus.PARTIAL, AnalysisStatus.INSUFFICIENT_DATA)

    @pytest.mark.asyncio
    async def test_incident_count_reflects_only_true_incidents(self, service, monkeypatch):
        # WARN-driven spike persisting across buckets should count 0
        # incidents even though it is anomalous.
        events = []
        pattern = [2, 3, 2, 3, 2]
        for bucket_idx, count in enumerate(pattern):
            bucket_start = -25 + bucket_idx * 5
            for i in range(count):
                events.append(_ev(bucket_start + i * 0.5, f"INFO baseline {bucket_idx}-{i}", "INFO"))
        for i in range(40):
            events.append(_ev(i * 0.1, f"WARN noisy retry {i}", "WARN"))

        async def fake_fetch(log_group_names, start_time, end_time, account_alias=None, query_string=None):
            return events

        monkeypatch.setattr(service, "fetch_classified_events", fake_fetch)

        result = await service.get_anomalies(
            log_group_names=["/aws/test"],
            time_range_preset=TimeRangePreset.CUSTOM,
            start_time=BASE,
            end_time=BASE + timedelta(minutes=5),
            bucket_minutes=5,
            history_periods=5,
        )
        assert result.incident_count == 0


# =============================================================================
# get_trends
# =============================================================================


class TestGetTrendsService:
    @pytest.mark.asyncio
    async def test_insufficient_baseline_when_no_history(self, service, monkeypatch):
        async def fake_fetch(log_group_names, start_time, end_time, account_alias=None, query_string=None):
            return [_ev(i, "INFO ok", "INFO") for i in range(5)]

        monkeypatch.setattr(service, "fetch_classified_events", fake_fetch)

        result = await service.get_trends(
            log_group_names=["/aws/test"],
            time_range_preset=TimeRangePreset.CUSTOM,
            start_time=BASE,
            end_time=BASE + timedelta(minutes=30),
            bucket_minutes=10,
            history_periods=0,
        )
        assert result.status == AnalysisStatus.INSUFFICIENT_DATA
        assert result.baseline_error_rate_per_minute is None
        assert result.change_from_baseline_pct is None
        assert len(result.points) == 3  # 30 minutes / 10-minute buckets

    @pytest.mark.asyncio
    async def test_error_rate_increase_vs_baseline(self, service, monkeypatch):
        # Baseline period [-30, 0): 2 errors. Current period [0, 30): 8 errors.
        baseline_errors = [_ev(-30 + i, "ERROR baseline", "ERROR") for i in range(2)]
        current_errors = [_ev(i, "ERROR current", "ERROR") for i in range(8)]

        async def fake_fetch(log_group_names, start_time, end_time, account_alias=None, query_string=None):
            return baseline_errors + current_errors

        monkeypatch.setattr(service, "fetch_classified_events", fake_fetch)

        result = await service.get_trends(
            log_group_names=["/aws/test"],
            time_range_preset=TimeRangePreset.CUSTOM,
            start_time=BASE,
            end_time=BASE + timedelta(minutes=30),
            bucket_minutes=30,
            history_periods=1,
        )
        assert result.baseline_error_rate_per_minute is not None
        assert result.current_error_rate_per_minute is not None
        assert result.current_error_rate_per_minute > result.baseline_error_rate_per_minute
        assert result.change_from_baseline_pct == pytest.approx(300.0)

    @pytest.mark.asyncio
    async def test_recurring_warnings_present_in_trends(self, service, monkeypatch):
        # 3 periods of 10 minutes (history_periods=2 -> total 3 periods
        # including current). A WARN pattern recurs in all 3.
        events = []
        for period in range(3):
            events.append(_ev(period * 10 + 1, "WARN retry budget exceeded", "WARN"))

        async def fake_fetch(log_group_names, start_time, end_time, account_alias=None, query_string=None):
            return events

        monkeypatch.setattr(service, "fetch_classified_events", fake_fetch)

        result = await service.get_trends(
            log_group_names=["/aws/test"],
            time_range_preset=TimeRangePreset.CUSTOM,
            start_time=BASE + timedelta(minutes=20),
            end_time=BASE + timedelta(minutes=30),
            bucket_minutes=10,
            history_periods=2,
            recurring_min_periods=2,
        )
        recurring = [r for r in result.recurring_warnings if r.is_recurring]
        assert len(recurring) == 1
        assert recurring[0].periods_seen == 3


# =============================================================================
# API-level wiring tests (TestClient, with the service's AWS-facing method
# monkeypatched so results stay deterministic)
# =============================================================================


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from app.main import app

    return TestClient(app)


class TestMockAdapterNativeHooks:
    """Adapter-level checks for the optional pattern/anomaly-detector
    contract added to the mock adapter. Not used by PatternAnalysisService
    by default (see its module docstring), but exercised directly here so
    the contract itself stays correct."""

    @pytest.mark.asyncio
    async def test_mock_start_pattern_query_returns_clustered_rows(self):
        from app.adapters.aws.mock import MockCloudWatchLogsAdapter

        adapter = MockCloudWatchLogsAdapter()
        query_id = await adapter.start_pattern_query(
            log_group_names=["/aws/ecs/prod-api"],
            start_time=0,
            end_time=3600,
        )
        # Poll until complete (mock completes after 2-3 polls).
        result = None
        for _ in range(5):
            result = await adapter.get_query_results(query_id)
            if result["status"] == "Complete":
                break
        assert result["status"] == "Complete"
        assert len(result["results"]) > 0
        fields = {item["field"] for item in result["results"][0]}
        assert "@pattern" in fields
        assert "@sampleCount" in fields
        assert "@severityLabel" in fields

    @pytest.mark.asyncio
    async def test_mock_anomaly_detectors_empty_by_default(self):
        from app.adapters.aws.mock import MockCloudWatchLogsAdapter

        adapter = MockCloudWatchLogsAdapter()
        detectors = await adapter.list_log_anomaly_detectors()
        assert detectors == []

    @pytest.mark.asyncio
    async def test_mock_list_anomalies_raises_feature_not_supported(self):
        from app.adapters.aws.base import AWSFeatureNotSupportedError
        from app.adapters.aws.mock import MockCloudWatchLogsAdapter

        adapter = MockCloudWatchLogsAdapter()
        with pytest.raises(AWSFeatureNotSupportedError):
            await adapter.list_anomalies("arn:aws:logs:us-east-1:123456789012:anomaly-detector:fake")


class TestAnalyticsAPI:
    def test_patterns_requires_log_group(self, client):
        response = client.get("/api/analytics/patterns")
        assert response.status_code == 422  # FastAPI query validation (required param missing)

    def test_patterns_endpoint_end_to_end(self, client, monkeypatch):
        async def fake_fetch(self, log_group_names, start_time, end_time, account_alias=None, query_string=None):
            return [_ev(0, "ERROR consistent failure", "ERROR") for _ in range(3)]

        monkeypatch.setattr(PatternAnalysisService, "fetch_classified_events", fake_fetch)

        response = client.get(
            "/api/analytics/patterns",
            params={
                "log_group": "/aws/ecs/prod-api",
                "start_time": BASE.isoformat(),
                "end_time": (BASE + timedelta(minutes=10)).isoformat(),
                "baseline_periods": 0,
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["success"] is True
        assert body["data"]["total_events"] == 3
        assert body["data"]["status"] == "partial"

    def test_anomalies_endpoint_end_to_end(self, client, monkeypatch):
        async def fake_fetch(self, log_group_names, start_time, end_time, account_alias=None, query_string=None):
            return [_ev(i, "INFO steady", "INFO") for i in range(5)]

        monkeypatch.setattr(PatternAnalysisService, "fetch_classified_events", fake_fetch)

        response = client.get(
            "/api/analytics/anomalies",
            params={
                "log_group": "/aws/ecs/prod-api",
                "start_time": BASE.isoformat(),
                "end_time": (BASE + timedelta(minutes=10)).isoformat(),
                "history_periods": 0,
            },
        )
        assert response.status_code == 200
        body = response.json()["data"]
        assert body["status"] == "insufficient_data"
        assert body["incident_count"] == 0

    def test_trends_endpoint_end_to_end(self, client, monkeypatch):
        async def fake_fetch(self, log_group_names, start_time, end_time, account_alias=None, query_string=None):
            return [_ev(i, "INFO steady", "INFO") for i in range(5)]

        monkeypatch.setattr(PatternAnalysisService, "fetch_classified_events", fake_fetch)

        response = client.get(
            "/api/analytics/trends",
            params={
                "log_group": "/aws/ecs/prod-api",
                "start_time": BASE.isoformat(),
                "end_time": (BASE + timedelta(minutes=30)).isoformat(),
                "bucket_minutes": 10,
                "history_periods": 0,
            },
        )
        assert response.status_code == 200
        body = response.json()["data"]
        assert len(body["points"]) == 3
        assert body["status"] == "insufficient_data"
