"""Deterministic tests for the CloudWatch anomaly and pattern analysis module.

All tests here use fixed, synthetic timestamps and hand-constructed
datasets (no reliance on `datetime.now()` or the randomized mock AWS
adapter) so results are 100% reproducible.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta

import pytest

from app.analytics.anomaly import AnomalyDetector
from app.analytics.baseline import (
    bucketize,
    has_sufficient_history,
    mean_stddev,
    partition_into_periods,
)
from app.analytics.patterns import diff_patterns, extract_patterns
from app.analytics.resource_signals import analyze_resource_signal
from app.analytics.severity import label_for_score, score_from_classification, score_log_pattern
from app.analytics.trends import (
    build_trend_points,
    compare_to_baseline_error_rate,
    detect_error_rate_anomalies,
    detect_frequency_spikes,
    find_recurring_warnings,
)
from app.schemas.analytics import AnalysisStatus, AnomalyClassification, LogPattern, SeverityLabel
from app.schemas.intelligence import LogSeverity

BASE = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)


def _ev(minute: float, message: str, severity: str = "INFO", log_group: str = "/aws/test") -> dict:
    return {
        "timestamp": BASE + timedelta(minutes=minute),
        "message": message,
        "severity": severity,
        "log_group": log_group,
        "ptr": None,
    }


# =============================================================================
# baseline.py
# =============================================================================


class TestBucketize:
    def test_empty_events_produces_zero_buckets_with_zero_counts(self):
        buckets = bucketize([], BASE, BASE + timedelta(minutes=10), bucket_minutes=5)
        assert len(buckets) == 2
        assert all(b.count == 0 for b in buckets)

    def test_counts_assigned_to_correct_bucket(self):
        events = [
            _ev(0, "a", "INFO"),
            _ev(1, "b", "ERROR"),
            _ev(6, "c", "WARN"),
            _ev(9.9, "d", "ERROR"),
        ]
        buckets = bucketize(events, BASE, BASE + timedelta(minutes=10), bucket_minutes=5)
        assert len(buckets) == 2
        assert buckets[0].count == 2
        assert buckets[0].error_count == 1
        assert buckets[1].count == 2
        assert buckets[1].error_count == 1
        assert buckets[1].warn_count == 1

    def test_event_before_range_start_is_dropped(self):
        events = [_ev(-5, "early", "ERROR")]
        buckets = bucketize(events, BASE, BASE + timedelta(minutes=10), bucket_minutes=5)
        assert sum(b.count for b in buckets) == 0

    def test_event_at_exact_range_end_clamped_to_last_bucket(self):
        events = [_ev(10, "boundary", "ERROR")]
        buckets = bucketize(events, BASE, BASE + timedelta(minutes=10), bucket_minutes=5)
        assert buckets[-1].count == 1

    def test_invalid_bucket_minutes_raises(self):
        with pytest.raises(ValueError):
            bucketize([], BASE, BASE + timedelta(minutes=10), bucket_minutes=0)

    def test_empty_range_returns_no_buckets(self):
        assert bucketize([], BASE, BASE, bucket_minutes=5) == []


class TestPartitionIntoPeriods:
    def test_splits_events_into_equal_periods(self):
        events = [_ev(1, "p0"), _ev(11, "p1"), _ev(21, "p2")]
        periods = partition_into_periods(events, BASE, BASE + timedelta(minutes=30), period_minutes=10)
        assert len(periods) == 3
        assert len(periods[0].events) == 1
        assert len(periods[1].events) == 1
        assert len(periods[2].events) == 1

    def test_insufficient_range_returns_empty(self):
        assert partition_into_periods([], BASE, BASE, period_minutes=10) == []


class TestMeanStddev:
    def test_empty_list(self):
        assert mean_stddev([]) == (0.0, 0.0)

    def test_single_value_has_zero_stddev(self):
        mean, stddev = mean_stddev([5.0])
        assert mean == 5.0
        assert stddev == 0.0

    def test_known_values(self):
        mean, stddev = mean_stddev([1, 2, 3, 4, 5])
        assert mean == 3.0
        assert math.isclose(stddev, math.sqrt(2.5))


class TestHasSufficientHistory:
    def test_boundary(self):
        assert has_sufficient_history(5, 5) is True
        assert has_sufficient_history(4, 5) is False


# =============================================================================
# severity.py
# =============================================================================


class TestSeverityScoring:
    def test_classification_baseline_points(self):
        score, label = score_from_classification(AnomalyClassification.NORMAL, None)
        assert score == 0.0
        assert label == SeverityLabel.LOW

        score, _ = score_from_classification(AnomalyClassification.WATCH, None)
        assert score == 15.0

        score, _ = score_from_classification(AnomalyClassification.ANOMALY, None)
        assert score == 40.0

        score, _ = score_from_classification(AnomalyClassification.INCIDENT, None)
        assert score == 55.0

    def test_magnitude_bonus_tiers(self):
        score_low, _ = score_from_classification(AnomalyClassification.ANOMALY, 2.0)
        score_mid, _ = score_from_classification(AnomalyClassification.ANOMALY, 3.0)
        score_high, _ = score_from_classification(AnomalyClassification.ANOMALY, 5.0)
        assert score_low == 48.0  # 40 + 8
        assert score_mid == 55.0  # 40 + 15
        assert score_high == 65.0  # 40 + 25

    def test_score_caps_at_incident_plus_max_magnitude_bonus(self):
        # INCIDENT (55) + max magnitude bonus (25, for |z| >= 5) = 80; the
        # 100-point ceiling exists as a safety clamp but documented scoring
        # never actually produces more than 80 today.
        score, label = score_from_classification(AnomalyClassification.INCIDENT, 10.0)
        assert score == 80.0
        assert label == SeverityLabel.CRITICAL

    def test_label_boundaries(self):
        assert label_for_score(0) == SeverityLabel.LOW
        assert label_for_score(24.9) == SeverityLabel.LOW
        assert label_for_score(25) == SeverityLabel.MEDIUM
        assert label_for_score(49.9) == SeverityLabel.MEDIUM
        assert label_for_score(50) == SeverityLabel.HIGH
        assert label_for_score(74.9) == SeverityLabel.HIGH
        assert label_for_score(75) == SeverityLabel.CRITICAL
        assert label_for_score(100) == SeverityLabel.CRITICAL

    def _pattern(self, severity: LogSeverity, ratio: float) -> LogPattern:
        return LogPattern(
            pattern_id="x",
            normalized_pattern="x",
            severity=severity,
            occurrence_count=1,
            ratio=ratio,
            first_seen=BASE,
            last_seen=BASE,
            representative_message="x",
        )

    def test_pattern_scoring_error_new_high_ratio(self):
        pattern = self._pattern(LogSeverity.ERROR, ratio=0.5)
        score, label = score_log_pattern(pattern, is_new=True, is_increasing=False)
        assert score == 40.0 + 25.0 + 20.0  # 85
        assert label == SeverityLabel.CRITICAL

    def test_pattern_scoring_info_not_new_low_ratio(self):
        pattern = self._pattern(LogSeverity.INFO, ratio=0.01)
        score, label = score_log_pattern(pattern, is_new=False, is_increasing=False)
        assert score == 5.0
        assert label == SeverityLabel.LOW

    def test_pattern_scoring_warn_increasing_mid_ratio(self):
        pattern = self._pattern(LogSeverity.WARN, ratio=0.15)
        score, _ = score_log_pattern(pattern, is_new=False, is_increasing=True)
        assert score == 20.0 + 15.0 + 10.0  # 45


# =============================================================================
# anomaly.py
# =============================================================================


class TestAnomalyDetectorPoint:
    def test_insufficient_history_is_normal_with_explanation(self):
        detector = AnomalyDetector()
        result = detector.evaluate_point(observed=100, history=[1, 2])
        assert result.classification == AnomalyClassification.NORMAL
        assert result.z_score is None
        assert "historical data point" in result.explanation[0]

    def test_zero_variance_exact_match_is_normal(self):
        detector = AnomalyDetector()
        result = detector.evaluate_point(observed=10, history=[10, 10, 10, 10, 10])
        assert result.classification == AnomalyClassification.NORMAL
        assert result.z_score is None

    def test_zero_variance_deviation_is_watch_not_anomaly(self):
        detector = AnomalyDetector()
        result = detector.evaluate_point(observed=50, history=[10, 10, 10, 10, 10])
        # Zero-variance baselines can never be quantified into an ANOMALY
        # (no magnitude to measure), only flagged as WATCH.
        assert result.classification == AnomalyClassification.WATCH

    def test_known_z_score_computation(self):
        detector = AnomalyDetector()
        history = [1, 2, 3, 4, 5]  # mean=3.0, stdev=sqrt(2.5)
        result = detector.evaluate_point(observed=9, history=history)
        expected_z = (9 - 3.0) / math.sqrt(2.5)
        assert math.isclose(result.z_score, expected_z)
        assert result.classification == AnomalyClassification.ANOMALY

    def test_anomaly_requires_min_absolute_count(self):
        from app.schemas.analytics import AnomalyThresholds

        # Small history with low values; z-score will clear the anomaly
        # threshold but the observed count is below min_absolute_count.
        detector = AnomalyDetector(AnomalyThresholds(min_absolute_count=10))
        history = [0, 0, 0, 0, 0]
        result = detector.evaluate_point(observed=2, history=history)
        # stddev is 0 here -> WATCH branch, but even WATCH requires
        # min_absolute_count to be cleared; 2 < 10 -> NORMAL.
        assert result.classification == AnomalyClassification.NORMAL


class TestAnomalyDetectorSeries:
    def _buckets(self, counts: list[int], error_counts: list[int] | None = None):
        from app.analytics.baseline import TimeBucket

        error_counts = error_counts or [0] * len(counts)
        buckets = []
        for i, (count, err) in enumerate(zip(counts, error_counts, strict=True)):
            start = BASE + timedelta(minutes=i * 5)
            buckets.append(TimeBucket(start=start, end=start + timedelta(minutes=5), count=count, error_count=err))
        return buckets

    def test_leading_buckets_without_history_are_skipped(self):
        from app.schemas.analytics import AnomalyThresholds

        detector = AnomalyDetector(AnomalyThresholds(min_history_points=5))
        buckets = self._buckets([1, 1, 1, 1, 1, 1])  # 6 buckets, need 5 history
        results = detector.evaluate_series(buckets, "freq", value_fn=lambda b: float(b.count))
        # Only the 6th bucket (index 5) has 5 preceding buckets of history.
        assert len(results) == 1
        assert results[0].bucket_start == buckets[5].start

    def test_spike_detected_after_baseline_with_variance(self):
        from app.schemas.analytics import AnomalyThresholds

        detector = AnomalyDetector(AnomalyThresholds(min_history_points=5, min_absolute_count=3))
        # 5 mildly-varying baseline buckets (mean=2.4, stdev~0.548), then a
        # clear spike (count=50). A perfectly flat baseline has zero
        # variance and can only ever reach WATCH (see
        # test_zero_variance_deviation_is_watch_not_anomaly) -- real
        # baselines normally have some variance, which is what lets a
        # magnitude actually be quantified into ANOMALY.
        buckets = self._buckets([2, 3, 2, 3, 2, 50])
        results = detector.evaluate_series(buckets, "freq", value_fn=lambda b: float(b.count))
        assert len(results) == 1
        assert results[0].classification == AnomalyClassification.ANOMALY
        assert results[0].observed_value == 50.0

    def test_warn_driven_anomaly_never_becomes_incident(self):
        """A recurring WARN-level spike must never be promoted to INCIDENT,
        however many consecutive buckets it persists for."""
        from app.schemas.analytics import AnomalyThresholds

        thresholds = AnomalyThresholds(min_history_points=3, min_absolute_count=3, min_consecutive_for_incident=2)
        detector = AnomalyDetector(thresholds)
        # 3 mildly-varying history buckets, then 4 consecutive WARN-driven spikes.
        counts = [1, 2, 1, 40, 40, 40, 40]
        buckets = self._buckets(counts)

        def warn_severity(_bucket):
            return LogSeverity.WARN

        results = detector.evaluate_series(buckets, "freq", value_fn=lambda b: float(b.count), severity_fn=warn_severity)
        assert len(results) == 4
        assert all(r.classification == AnomalyClassification.ANOMALY for r in results)
        assert all(r.is_incident is False for r in results)

    def test_error_driven_anomaly_promoted_to_incident_after_persistence(self):
        from app.schemas.analytics import AnomalyThresholds

        thresholds = AnomalyThresholds(min_history_points=3, min_absolute_count=3, min_consecutive_for_incident=2)
        detector = AnomalyDetector(thresholds)
        counts = [1, 2, 1, 40, 40, 40]
        buckets = self._buckets(counts)

        def error_severity(_bucket):
            return LogSeverity.ERROR

        results = detector.evaluate_series(buckets, "freq", value_fn=lambda b: float(b.count), severity_fn=error_severity)
        assert len(results) == 3
        # First anomalous bucket: streak=1, below min_consecutive_for_incident=2.
        assert results[0].classification == AnomalyClassification.ANOMALY
        assert results[0].is_incident is False
        # Second and third: streak>=2 -> promoted to INCIDENT.
        assert results[1].classification == AnomalyClassification.INCIDENT
        assert results[1].is_incident is True
        assert results[2].is_incident is True

    def test_single_statistical_blip_is_not_an_incident(self):
        """A lone statistical anomaly (no persistence) is never an incident,
        even when error-driven."""
        from app.schemas.analytics import AnomalyThresholds

        thresholds = AnomalyThresholds(min_history_points=3, min_absolute_count=3, min_consecutive_for_incident=3)
        detector = AnomalyDetector(thresholds)
        counts = [1, 2, 1, 40, 1]  # single spike then back to normal
        buckets = self._buckets(counts)
        results = detector.evaluate_series(
            buckets, "freq", value_fn=lambda b: float(b.count), severity_fn=lambda b: LogSeverity.ERROR
        )
        assert results[0].classification == AnomalyClassification.ANOMALY
        assert results[0].is_incident is False


# =============================================================================
# patterns.py
# =============================================================================


class TestExtractPatterns:
    def test_empty_events(self):
        assert extract_patterns([]) == []

    def test_groups_identical_shapes_and_counts_occurrences(self):
        events = [
            _ev(0, "ERROR timeout connecting to host 10.0.0.5", "ERROR"),
            _ev(1, "ERROR timeout connecting to host 10.0.0.9", "ERROR"),
            _ev(2, "INFO health check ok", "INFO"),
        ]
        patterns = extract_patterns(events)
        assert len(patterns) == 2
        top = patterns[0]
        assert top.occurrence_count == 2
        assert top.severity == LogSeverity.ERROR
        assert math.isclose(top.ratio, 2 / 3)

    def test_min_occurrences_filters_rare_patterns(self):
        events = [_ev(0, "ERROR rare issue", "ERROR")]
        assert extract_patterns(events, min_occurrences=2) == []
        assert len(extract_patterns(events, min_occurrences=1)) == 1

    def test_first_last_seen_tracked(self):
        events = [
            _ev(0, "ERROR boom", "ERROR"),
            _ev(50, "ERROR boom", "ERROR"),
        ]
        patterns = extract_patterns(events)
        assert patterns[0].first_seen == BASE
        assert patterns[0].last_seen == BASE + timedelta(minutes=50)


class TestDiffPatterns:
    def test_new_pattern_detected_and_scored(self):
        current = extract_patterns([_ev(0, "ERROR new failure mode", "ERROR")])
        baseline: list[LogPattern] = []
        diff = diff_patterns(current, baseline)
        assert len(diff.new_patterns) == 1
        assert diff.new_patterns[0].is_new is True
        assert diff.new_patterns[0].severity_score > 0

    def test_disappeared_pattern_detected(self):
        current: list[LogPattern] = []
        baseline = extract_patterns([_ev(0, "ERROR old failure", "ERROR")])
        diff = diff_patterns(current, baseline)
        assert len(diff.disappeared_patterns) == 1

    def test_increased_pattern_detected(self):
        baseline_events = [_ev(i, "WARN retry", "WARN") for i in range(1)] + [
            _ev(10, "INFO noise", "INFO") for _ in range(9)
        ]  # WARN ratio = 1/10 = 0.1
        current_events = [_ev(i, "WARN retry", "WARN") for i in range(5)] + [
            _ev(10, "INFO noise", "INFO") for _ in range(5)
        ]  # WARN ratio = 5/10 = 0.5
        baseline = extract_patterns(baseline_events)
        current = extract_patterns(current_events)
        diff = diff_patterns(current, baseline, change_ratio_threshold=0.5)
        warn_ids = {p.pattern_id for p in extract_patterns([_ev(0, "WARN retry", "WARN")])}
        assert any(p.pattern_id in warn_ids for p in diff.increased_patterns)

    def test_decreased_pattern_detected(self):
        baseline_events = [_ev(i, "WARN retry", "WARN") for i in range(5)] + [
            _ev(10, "INFO noise", "INFO") for _ in range(5)
        ]
        current_events = [_ev(i, "WARN retry", "WARN") for i in range(1)] + [
            _ev(10, "INFO noise", "INFO") for _ in range(9)
        ]
        baseline = extract_patterns(baseline_events)
        current = extract_patterns(current_events)
        diff = diff_patterns(current, baseline, change_ratio_threshold=0.5)
        assert len(diff.decreased_patterns) == 1

    def test_stable_pattern_is_neither_increased_nor_decreased(self):
        events = [_ev(i, "INFO steady state", "INFO") for i in range(10)]
        baseline = extract_patterns(events)
        current = extract_patterns(events)
        diff = diff_patterns(current, baseline)
        assert diff.new_patterns == []
        assert diff.disappeared_patterns == []
        assert diff.increased_patterns == []
        assert diff.decreased_patterns == []


# =============================================================================
# trends.py
# =============================================================================


class TestBuildTrendPoints:
    def test_error_rate_per_minute_computed(self):
        buckets = bucketize(
            [_ev(0, "e", "ERROR"), _ev(1, "e", "ERROR"), _ev(2, "w", "WARN")],
            BASE,
            BASE + timedelta(minutes=5),
            bucket_minutes=5,
        )
        points = build_trend_points(buckets)
        assert len(points) == 1
        assert points[0].error_count == 2
        assert points[0].warn_count == 1
        assert math.isclose(points[0].error_rate_per_minute, 2 / 5)


class TestCompareToBaselineErrorRate:
    def test_insufficient_data_when_baseline_empty(self):
        current = bucketize([_ev(0, "e", "ERROR")], BASE, BASE + timedelta(minutes=5), 5)
        current_epm, baseline_epm, pct = compare_to_baseline_error_rate(current, [])
        assert current_epm is not None
        assert baseline_epm is None
        assert pct is None

    def test_known_percentage_increase(self):
        baseline_events = [_ev(i, "e", "ERROR") for i in range(2)]  # 2 errors / 5 min
        current_events = [_ev(i, "e", "ERROR") for i in range(8)]  # 8 errors / 5 min
        baseline = bucketize(baseline_events, BASE, BASE + timedelta(minutes=5), 5)
        current = bucketize(current_events, BASE, BASE + timedelta(minutes=5), 5)
        current_epm, baseline_epm, pct = compare_to_baseline_error_rate(current, baseline)
        assert math.isclose(baseline_epm, 2 / 5)
        assert math.isclose(current_epm, 8 / 5)
        assert math.isclose(pct, 300.0)  # (8-2)/2 * 100

    def test_no_current_buckets(self):
        assert compare_to_baseline_error_rate([], []) == (None, None, None)


class TestDetectFrequencyAndErrorRateSpikes:
    def test_frequency_spike_flagged(self):
        from app.analytics.baseline import TimeBucket
        from app.schemas.analytics import AnomalyThresholds

        baseline_counts = [2, 3, 2, 3, 2]  # mild variance, not a perfectly flat baseline
        buckets = [
            TimeBucket(BASE + timedelta(minutes=i * 5), BASE + timedelta(minutes=(i + 1) * 5), count=c)
            for i, c in enumerate(baseline_counts)
        ]
        buckets.append(
            TimeBucket(BASE + timedelta(minutes=25), BASE + timedelta(minutes=30), count=100, error_count=100)
        )
        results = detect_frequency_spikes(buckets, AnomalyThresholds(min_history_points=5))
        assert len(results) == 1
        assert results[0].classification == AnomalyClassification.ANOMALY

    def test_error_rate_anomaly_ignores_non_error_volume(self):
        from app.analytics.baseline import TimeBucket
        from app.schemas.analytics import AnomalyThresholds

        # High total volume but all WARN -- error_rate series stays flat at 0.
        buckets = [
            TimeBucket(BASE + timedelta(minutes=i * 5), BASE + timedelta(minutes=(i + 1) * 5), count=5, warn_count=5)
            for i in range(6)
        ]
        results = detect_error_rate_anomalies(buckets, AnomalyThresholds(min_history_points=5))
        assert len(results) == 1
        assert results[0].classification == AnomalyClassification.NORMAL


class TestFindRecurringWarnings:
    def test_insufficient_data_single_period(self):
        periods = partition_into_periods(
            [_ev(0, "WARN x", "WARN")], BASE, BASE + timedelta(minutes=10), period_minutes=10
        )
        assert find_recurring_warnings(periods) == []

    def test_recurring_vs_one_off(self):
        # 5 periods of 10 minutes each. "WARN retry" appears in periods 0,1,2,4.
        # "WARN one-off" appears only in period 3.
        events = []
        for period in (0, 1, 2, 4):
            events.append(_ev(period * 10 + 1, "WARN retry budget exceeded", "WARN"))
        events.append(_ev(3 * 10 + 1, "WARN one-off blip", "WARN"))

        periods = partition_into_periods(events, BASE, BASE + timedelta(minutes=50), period_minutes=10)
        assert len(periods) == 5

        results = find_recurring_warnings(periods, min_periods_seen=2)
        by_message = {r.representative_message: r for r in results}

        recurring = by_message["WARN retry budget exceeded"]
        assert recurring.periods_seen == 4
        assert recurring.is_recurring is True
        assert math.isclose(recurring.historical_frequency, 4 / 5)

        one_off = by_message["WARN one-off blip"]
        assert one_off.periods_seen == 1
        assert one_off.is_recurring is False

    def test_ignores_non_warn_severities(self):
        events = [_ev(0, "ERROR boom", "ERROR"), _ev(11, "ERROR boom", "ERROR")]
        periods = partition_into_periods(events, BASE, BASE + timedelta(minutes=20), period_minutes=10)
        assert find_recurring_warnings(periods) == []


# =============================================================================
# resource_signals.py
# =============================================================================


class _StubMetricsAdapter:
    mode = "mock"

    def __init__(self, values=None, exc: Exception | None = None):
        self._values = values or []
        self._exc = exc

    async def list_metrics(self, namespace=None, metric_name=None):
        return []

    async def get_metric_data(self, metric_name: str, namespace: str):
        if self._exc:
            raise self._exc
        return {"namespace": namespace, "metricName": metric_name, "values": self._values}


class TestAnalyzeResourceSignal:
    @pytest.mark.asyncio
    async def test_unavailable_when_adapter_raises_not_implemented(self):
        from app.adapters.aws.base import AdapterNotImplementedError

        adapter = _StubMetricsAdapter(exc=AdapterNotImplementedError("no metrics"))
        signal = await analyze_resource_signal(adapter, "AWS/ECS", "CPUUtilization")
        assert signal.status == AnalysisStatus.UNAVAILABLE

    @pytest.mark.asyncio
    async def test_error_status_on_unexpected_exception(self):
        adapter = _StubMetricsAdapter(exc=RuntimeError("boom"))
        signal = await analyze_resource_signal(adapter, "AWS/ECS", "CPUUtilization")
        assert signal.status == AnalysisStatus.ERROR

    @pytest.mark.asyncio
    async def test_insufficient_data_with_too_few_points(self):
        adapter = _StubMetricsAdapter(values=[42.0])
        signal = await analyze_resource_signal(adapter, "AWS/ECS", "CPUUtilization")
        assert signal.status == AnalysisStatus.INSUFFICIENT_DATA

    @pytest.mark.asyncio
    async def test_insufficient_data_below_min_history_points(self):
        from app.schemas.analytics import AnomalyThresholds

        adapter = _StubMetricsAdapter(values=[10.0, 11.0, 90.0])
        signal = await analyze_resource_signal(
            adapter, "AWS/ECS", "Latency", AnomalyThresholds(min_history_points=5)
        )
        assert signal.status == AnalysisStatus.INSUFFICIENT_DATA

    @pytest.mark.asyncio
    async def test_latency_spike_detected(self):
        from app.schemas.analytics import AnomalyThresholds

        values = [10.0, 11.0, 9.0, 10.0, 10.5, 200.0]  # last value is a clear spike
        adapter = _StubMetricsAdapter(values=values)
        signal = await analyze_resource_signal(
            adapter, "AWS/ApplicationELB", "TargetResponseTime", AnomalyThresholds(min_history_points=5)
        )
        assert signal.status == AnalysisStatus.OK
        assert len(signal.anomalies) == 1
        assert signal.anomalies[0].classification in (AnomalyClassification.WATCH, AnomalyClassification.ANOMALY)
        assert signal.anomalies[0].is_incident is False

    @pytest.mark.asyncio
    async def test_stable_series_is_normal_and_no_anomalies_listed(self):
        from app.schemas.analytics import AnomalyThresholds

        values = [10.0, 10.0, 10.0, 10.0, 10.0, 10.0]
        adapter = _StubMetricsAdapter(values=values)
        signal = await analyze_resource_signal(
            adapter, "AWS/ECS", "CPUUtilization", AnomalyThresholds(min_history_points=5)
        )
        assert signal.status == AnalysisStatus.OK
        assert signal.anomalies == []
