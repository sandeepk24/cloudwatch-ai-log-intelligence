"""Tests for Log Intelligence Engine."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.intelligence.classifiers import (
    ContextExtractor,
    LogClassifier,
    PatternDetector,
    SeverityClassifier,
)
from app.intelligence.engine import LogIntelligenceEngine
from app.intelligence.fingerprint import (
    EventDeduplicator,
    compute_fingerprint,
    extract_exception_type,
    is_stack_trace,
    normalize_message,
)
from app.intelligence.redaction import Redactor, redact_for_ai, redact_message
from app.intelligence.rules import (
    DEFAULT_PATTERN_RULES,
    DEFAULT_SEVERITY_RULES,
    DetectionRule,
    RuleType,
    get_all_rules,
)
from app.schemas.intelligence import (
    LogSeverity,
    PatternCategory,
)


# =============================================================================
# Severity Classification Tests
# =============================================================================


class TestSeverityClassifier:
    """Tests for SeverityClassifier."""

    def test_classify_error_keyword(self):
        classifier = SeverityClassifier()
        assert classifier.classify("ERROR: Something went wrong") == LogSeverity.ERROR
        assert classifier.classify("FATAL: System crash") == LogSeverity.ERROR
        assert classifier.classify("CRITICAL: Database down") == LogSeverity.ERROR

    def test_classify_warning_keyword(self):
        classifier = SeverityClassifier()
        assert classifier.classify("WARN: Memory usage high") == LogSeverity.WARN
        assert classifier.classify("WARNING: Connection slow") == LogSeverity.WARN

    def test_classify_info_keyword(self):
        classifier = SeverityClassifier()
        assert classifier.classify("INFO: Server started") == LogSeverity.INFO

    def test_classify_debug_keyword(self):
        classifier = SeverityClassifier()
        assert classifier.classify("DEBUG: Variable x=5") == LogSeverity.DEBUG

    def test_classify_unknown(self):
        classifier = SeverityClassifier()
        assert classifier.classify("Something happened") == LogSeverity.UNKNOWN

    def test_classify_from_structured_field(self):
        classifier = SeverityClassifier()
        assert classifier.classify("event occurred", {"level": "ERROR"}) == LogSeverity.ERROR
        assert classifier.classify("event occurred", {"severity": "WARN"}) == LogSeverity.WARN
        assert classifier.classify("event occurred", {"log_level": "info"}) == LogSeverity.INFO


# =============================================================================
# Pattern Detection Tests
# =============================================================================


class TestPatternDetector:
    """Tests for PatternDetector."""

    def test_detect_java_exception(self):
        detector = PatternDetector()
        message = "java.lang.NullPointerException: Cannot invoke method on null"
        patterns = detector.detect(message)

        assert len(patterns) >= 1
        java_patterns = [p for p in patterns if p.category == PatternCategory.JAVA_EXCEPTION]
        assert len(java_patterns) >= 1

    def test_detect_java_stacktrace(self):
        detector = PatternDetector()
        message = "at com.example.MyClass.method(MyClass.java:42)"
        patterns = detector.detect(message)

        java_patterns = [p for p in patterns if p.category == PatternCategory.JAVA_EXCEPTION]
        assert len(java_patterns) >= 1

    def test_detect_python_traceback(self):
        detector = PatternDetector()
        message = 'Traceback (most recent call last):\n  File "app.py", line 10'
        patterns = detector.detect(message)

        python_patterns = [p for p in patterns if p.category == PatternCategory.PYTHON_TRACEBACK]
        assert len(python_patterns) >= 1

    def test_detect_python_exception(self):
        detector = PatternDetector()
        message = "ValueError: invalid literal for int()"
        patterns = detector.detect(message)

        python_patterns = [p for p in patterns if p.category == PatternCategory.PYTHON_TRACEBACK]
        assert len(python_patterns) >= 1

    def test_detect_http_5xx(self):
        detector = PatternDetector()
        message = "HTTP/1.1 500 Internal Server Error"
        patterns = detector.detect(message)

        http_patterns = [p for p in patterns if p.category == PatternCategory.HTTP_SERVER_ERROR]
        assert len(http_patterns) >= 1

    def test_detect_http_4xx(self):
        detector = PatternDetector()
        message = "GET /api/users 404 Not Found"
        patterns = detector.detect(message)

        http_patterns = [p for p in patterns if p.category == PatternCategory.HTTP_CLIENT_ERROR]
        assert len(http_patterns) >= 1

    def test_false_positive_http_port(self):
        detector = PatternDetector()
        message = "Listening on port=8080"
        patterns = detector.detect(message)

        # Should not detect as HTTP error
        http_patterns = [
            p for p in patterns
            if p.category in (PatternCategory.HTTP_CLIENT_ERROR, PatternCategory.HTTP_SERVER_ERROR)
            and not p.is_false_positive
        ]
        assert len(http_patterns) == 0

    def test_detect_oom(self):
        detector = PatternDetector()
        patterns = detector.detect("java.lang.OutOfMemoryError: heap space")
        oom_patterns = [p for p in patterns if p.category == PatternCategory.OUT_OF_MEMORY]
        assert len(oom_patterns) >= 1

    def test_detect_timeout(self):
        detector = PatternDetector()
        patterns = detector.detect("Connection timed out after 30 seconds")
        timeout_patterns = [p for p in patterns if p.category == PatternCategory.CONNECTION_TIMEOUT]
        assert len(timeout_patterns) >= 1

    def test_detect_throttling(self):
        detector = PatternDetector()
        patterns = detector.detect("ThrottlingException: Rate exceeded")
        throttle_patterns = [p for p in patterns if p.category == PatternCategory.THROTTLING]
        assert len(throttle_patterns) >= 1

    def test_detect_database_error(self):
        detector = PatternDetector()
        patterns = detector.detect("Failed to connect to database: connection refused")
        db_patterns = [p for p in patterns if p.category == PatternCategory.DATABASE_ERROR]
        assert len(db_patterns) >= 1


# =============================================================================
# Context Extraction Tests
# =============================================================================


class TestContextExtractor:
    """Tests for ContextExtractor."""

    def test_extract_request_id(self):
        extractor = ContextExtractor()
        context = extractor.extract("request_id=abc123def456")
        assert context.request_id == "abc123def456"

    def test_extract_trace_id(self):
        extractor = ContextExtractor()
        context = extractor.extract("trace_id=1234567890abcdef1234567890abcdef")
        assert context.trace_id == "1234567890abcdef1234567890abcdef"

    def test_extract_service_name(self):
        extractor = ContextExtractor()
        context = extractor.extract("service=payment-api")
        assert context.service_name == "payment-api"

    def test_extract_from_json(self):
        extractor = ContextExtractor()
        context = extractor.extract('{"service": "api-gateway", "version": "1.2.3"}')
        assert context.service_name == "api-gateway"
        assert context.deployment_version == "1.2.3"

    def test_extract_from_raw_fields(self):
        extractor = ContextExtractor()
        context = extractor.extract(
            "some message",
            raw_fields={
                "request_id": "req-123",
                "service_name": "my-service",
                "environment": "production",
            },
        )
        assert context.request_id == "req-123"
        assert context.service_name == "my-service"
        assert context.environment == "production"

    def test_extract_http_info(self):
        extractor = ContextExtractor()
        context = extractor.extract("GET /api/users HTTP/1.1 200")
        assert context.http_method == "GET"
        assert context.http_path == "/api/users"
        assert context.http_status == 200


# =============================================================================
# Fingerprinting Tests
# =============================================================================


class TestFingerprinting:
    """Tests for fingerprinting and normalization."""

    def test_normalize_uuid(self):
        msg = "Request abc12345-def6-7890-abcd-ef1234567890 failed"
        normalized = normalize_message(msg)
        assert "<UUID>" in normalized
        assert "abc12345" not in normalized

    def test_normalize_timestamp(self):
        msg = "Event at 2024-01-15T10:30:00Z processed"
        normalized = normalize_message(msg)
        assert "<TIMESTAMP>" in normalized

    def test_normalize_ip(self):
        msg = "Connection from 192.168.1.100"
        normalized = normalize_message(msg)
        assert "<IP>" in normalized

    def test_normalize_numbers(self):
        msg = "Processed 12345 records in 5678ms"
        normalized = normalize_message(msg)
        assert "12345" not in normalized
        assert "<DURATION>" in normalized or "<NUM>" in normalized

    def test_fingerprint_deterministic(self):
        msg = "NullPointerException: cannot invoke on null"
        fp1 = compute_fingerprint(msg)
        fp2 = compute_fingerprint(msg)
        assert fp1.fingerprint == fp2.fingerprint

    def test_fingerprint_similar_messages(self):
        msg1 = "Request abc12345-def6-7890-abcd-ef1234567890 failed"
        msg2 = "Request 11111111-2222-3333-4444-555555555555 failed"
        fp1 = compute_fingerprint(msg1)
        fp2 = compute_fingerprint(msg2)
        # Similar messages should have same fingerprint after normalization
        assert fp1.fingerprint == fp2.fingerprint

    def test_extract_exception_type(self):
        # Full qualified Java exception type is returned
        assert "NullPointerException" in extract_exception_type("java.lang.NullPointerException: msg")
        assert extract_exception_type("ValueError: invalid") == "ValueError"
        assert extract_exception_type("some other message") is None

    def test_is_stack_trace(self):
        assert is_stack_trace("at com.example.Class.method(Class.java:42)")
        assert is_stack_trace("Traceback (most recent call last):")
        assert is_stack_trace('File "app.py", line 10')
        assert not is_stack_trace("INFO: Normal log message")


class TestEventDeduplicator:
    """Tests for EventDeduplicator."""

    def test_add_unique_events(self):
        dedup = EventDeduplicator()
        from app.schemas.intelligence import ClassifiedEvent, ExtractedContext

        event1 = ClassifiedEvent(
            original_message="error 1",
            redacted_message="error 1",
            severity=LogSeverity.ERROR,
            fingerprint="fp1",
            timestamp=datetime.now(timezone.utc),
            log_group="/aws/test",
            context=ExtractedContext(),
        )
        event2 = ClassifiedEvent(
            original_message="error 2",
            redacted_message="error 2",
            severity=LogSeverity.ERROR,
            fingerprint="fp2",
            timestamp=datetime.now(timezone.utc),
            log_group="/aws/test",
            context=ExtractedContext(),
        )

        assert dedup.add_event(event1) is True  # New
        assert dedup.add_event(event2) is True  # New
        assert dedup.add_event(event1) is False  # Duplicate

    def test_get_stats(self):
        dedup = EventDeduplicator()
        from app.schemas.intelligence import ClassifiedEvent, ExtractedContext

        for i in range(5):
            event = ClassifiedEvent(
                original_message=f"error {i % 2}",
                redacted_message=f"error {i % 2}",
                severity=LogSeverity.ERROR,
                fingerprint=f"fp{i % 2}",
                timestamp=datetime.now(timezone.utc),
                log_group="/aws/test",
                context=ExtractedContext(),
            )
            dedup.add_event(event)

        stats = dedup.get_stats()
        assert stats["total_events"] == 5
        assert stats["unique_events"] == 2
        assert stats["deduplication_ratio"] == 0.6


# =============================================================================
# Redaction Tests
# =============================================================================


class TestRedaction:
    """Tests for sensitive data redaction."""

    def test_redact_aws_access_key(self):
        message = "Access key: AKIAIOSFODNN7EXAMPLE"
        redacted = redact_message(message)
        assert "AKIAIOSFODNN7EXAMPLE" not in redacted
        assert "[AWS_ACCESS_KEY]" in redacted

    def test_redact_email(self):
        message = "User email: user@example.com"
        redacted = redact_for_ai(message)
        assert "user@example.com" not in redacted
        assert "[EMAIL]" in redacted

    def test_redact_jwt(self):
        message = "Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        redacted = redact_message(message)
        assert "eyJ" not in redacted
        assert "[JWT]" in redacted

    def test_redact_password_field(self):
        message = "password=secret123"
        redacted = redact_message(message)
        assert "secret123" not in redacted
        assert "[REDACTED]" in redacted

    def test_redact_connection_string(self):
        message = "Connecting to postgres://user:pass@localhost/db"
        redacted = redact_message(message)
        assert "postgres://" not in redacted
        assert "[CONNECTION_STRING]" in redacted

    def test_redact_api_key(self):
        message = "api_key=sk_live_abcdef1234567890abcdef"
        redacted = redact_message(message)
        assert "sk_live" not in redacted
        assert "[API_KEY]" in redacted

    def test_redact_preserves_normal_content(self):
        message = "INFO: Server started on port 8080"
        redacted = redact_message(message)
        assert "Server started" in redacted
        assert "8080" in redacted

    def test_redactor_dict(self):
        redactor = Redactor()
        data = {
            "message": "User user@example.com logged in",
            "password": "secret",
            "api_key": "sk_live_1234567890abcdefghij",
        }
        redacted = redactor.redact_dict(data)
        assert redacted["password"] == "[REDACTED]"
        assert "user@example.com" not in redacted["message"]
        assert redacted["api_key"] == "[REDACTED]"


# =============================================================================
# Detection Rules Tests
# =============================================================================


class TestDetectionRules:
    """Tests for detection rules."""

    def test_get_all_rules(self):
        rules = get_all_rules()
        assert len(rules) > 0
        assert all(isinstance(r, DetectionRule) for r in rules)

    def test_rule_matches(self):
        rule = DetectionRule(
            id="test",
            name="Test Rule",
            description="Test",
            category=PatternCategory.JAVA_EXCEPTION,
            rule_type=RuleType.REGEX,
            pattern=r"(?P<type>\w+Exception):\s*(?P<msg>.+)",
            confidence=0.9,
        )
        matched, extracted = rule.matches("NullPointerException: cannot call method")
        assert matched
        assert extracted.get("type") == "NullPointerException"
        assert "cannot call" in extracted.get("msg", "")

    def test_rule_false_positive(self):
        rule = DetectionRule(
            id="test",
            name="Test Rule",
            description="Test",
            category=PatternCategory.HTTP_CLIENT_ERROR,
            rule_type=RuleType.REGEX,
            pattern=r"\b4\d{2}\b",
            confidence=0.9,
            false_positive_patterns=[r"port\s*[=:]\s*4\d{2}"],
        )
        assert rule.is_false_positive("port=443")[0] is True
        assert rule.is_false_positive("HTTP 404 Not Found")[0] is False


# =============================================================================
# LogClassifier Integration Tests
# =============================================================================


class TestLogClassifier:
    """Tests for integrated LogClassifier."""

    def test_classify_java_error(self):
        classifier = LogClassifier()
        severity, patterns, context = classifier.classify(
            "ERROR java.lang.NullPointerException: Cannot invoke method"
        )
        assert severity == LogSeverity.ERROR
        java_patterns = [p for p in patterns if p.category == PatternCategory.JAVA_EXCEPTION]
        assert len(java_patterns) >= 1

    def test_classify_elevates_severity(self):
        classifier = LogClassifier()
        # Even without ERROR keyword, exception should elevate severity
        severity, patterns, context = classifier.classify(
            "java.lang.OutOfMemoryError: Java heap space"
        )
        assert severity == LogSeverity.ERROR

    def test_classify_with_context(self):
        classifier = LogClassifier()
        severity, patterns, context = classifier.classify(
            "ERROR processing request_id=abc123def456 service=payment-api",
            raw_fields={"environment": "prod"},
        )
        assert context.request_id == "abc123def456"
        assert context.service_name == "payment-api"
        assert context.environment == "prod"


# =============================================================================
# Intelligence Engine Integration Tests
# =============================================================================


class TestLogIntelligenceEngine:
    """Tests for LogIntelligenceEngine."""

    def test_classify_single_event(self):
        engine = LogIntelligenceEngine()
        event = engine.classify_event(
            message="ERROR: java.lang.NullPointerException: null value",
            log_group="/aws/lambda/my-function",
        )
        assert event.severity == LogSeverity.ERROR
        assert len(event.fingerprint) > 0
        assert event.redacted_message is not None

    def test_classify_redacts_sensitive_data(self):
        engine = LogIntelligenceEngine(redact_pii=True)
        event = engine.classify_event(
            message="User user@example.com with api_key=sk_live_abcdef1234567890abcdef failed",
        )
        assert "user@example.com" not in event.redacted_message
        assert "sk_live" not in event.redacted_message

    def test_analyze_events_empty(self):
        engine = LogIntelligenceEngine()
        summary = engine.analyze_events([])
        assert summary.total_events_analyzed == 0
        assert summary.total_events_after_dedup == 0

    def test_analyze_events_basic(self):
        engine = LogIntelligenceEngine()
        events = [
            {
                "message": "ERROR: NullPointerException in MyService",
                "timestamp": datetime.now(timezone.utc),
                "log_group": "/aws/ecs/my-service",
            },
            {
                "message": "ERROR: NullPointerException in MyService",
                "timestamp": datetime.now(timezone.utc),
                "log_group": "/aws/ecs/my-service",
            },
            {
                "message": "INFO: Request completed successfully",
                "timestamp": datetime.now(timezone.utc),
                "log_group": "/aws/ecs/my-service",
            },
        ]
        summary = engine.analyze_events(events)

        assert summary.total_events_analyzed == 3
        assert summary.total_events_after_dedup < 3  # Duplicates removed
        assert summary.severity_distribution.error_count == 2
        assert summary.severity_distribution.info_count == 1

    def test_analyze_events_builds_clusters(self):
        engine = LogIntelligenceEngine()
        events = [
            {"message": "ERROR: Connection timeout to database", "timestamp": datetime.now(timezone.utc)},
            {"message": "ERROR: Connection timeout to database", "timestamp": datetime.now(timezone.utc)},
            {"message": "ERROR: Connection timeout to database", "timestamp": datetime.now(timezone.utc)},
            {"message": "ERROR: OutOfMemoryError: heap space", "timestamp": datetime.now(timezone.utc)},
        ]
        summary = engine.analyze_events(events)

        assert len(summary.failure_clusters) >= 1
        # Most common failure should have count 3
        top_cluster = summary.failure_clusters[0]
        assert top_cluster.occurrence_count >= 3

    def test_analyze_events_extracts_services(self):
        engine = LogIntelligenceEngine()
        events = [
            {"message": "ERROR service=api-gateway request failed", "timestamp": datetime.now(timezone.utc)},
            {"message": "ERROR service=payment-api timeout", "timestamp": datetime.now(timezone.utc)},
        ]
        summary = engine.analyze_events(events)

        assert "api-gateway" in summary.detected_services
        assert "payment-api" in summary.detected_services

    def test_analyze_events_calculates_error_rate(self):
        engine = LogIntelligenceEngine()
        events = [
            {"message": "ERROR: failure 1", "timestamp": datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)},
            {"message": "ERROR: failure 2", "timestamp": datetime(2024, 1, 1, 10, 1, 0, tzinfo=timezone.utc)},
            {"message": "ERROR: failure 3", "timestamp": datetime(2024, 1, 1, 10, 2, 0, tzinfo=timezone.utc)},
        ]
        summary = engine.analyze_events(events)

        # 3 errors over 2 minutes = 1.5 errors/minute
        assert summary.error_rate.errors_per_minute > 0
        assert summary.error_rate.time_window_minutes >= 2

    def test_analyze_with_baseline(self):
        engine = LogIntelligenceEngine()
        current_events = [
            {"message": "ERROR: failure", "timestamp": datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)},
            {"message": "ERROR: failure", "timestamp": datetime(2024, 1, 1, 10, 0, 30, tzinfo=timezone.utc)},
            {"message": "ERROR: failure", "timestamp": datetime(2024, 1, 1, 10, 1, 0, tzinfo=timezone.utc)},
            {"message": "ERROR: failure", "timestamp": datetime(2024, 1, 1, 10, 1, 30, tzinfo=timezone.utc)},
        ]
        baseline_events = [
            {"message": "ERROR: failure", "timestamp": datetime(2024, 1, 1, 9, 0, 0, tzinfo=timezone.utc)},
            {"message": "ERROR: failure", "timestamp": datetime(2024, 1, 1, 9, 1, 0, tzinfo=timezone.utc)},
        ]
        summary = engine.analyze_events(current_events, baseline_events=baseline_events)

        assert summary.error_rate.baseline_errors_per_minute is not None
        # Current rate should be higher than baseline
        assert summary.error_rate.change_percentage is not None

    def test_top_failures_ranked(self):
        engine = LogIntelligenceEngine()
        events = (
            [{"message": "ERROR: OOM killed", "timestamp": datetime.now(timezone.utc)}] * 5
            + [{"message": "ERROR: timeout", "timestamp": datetime.now(timezone.utc)}] * 3
            + [{"message": "ERROR: other", "timestamp": datetime.now(timezone.utc)}] * 1
        )
        summary = engine.analyze_events(events)

        assert len(summary.top_failures) >= 2
        # Top failure should have highest count
        assert summary.top_failures[0].cluster.occurrence_count >= summary.top_failures[1].cluster.occurrence_count


# =============================================================================
# API Integration Tests
# =============================================================================


@pytest.fixture
def client():
    """Create test client."""
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)


class TestIntelligenceAPI:
    """Tests for intelligence API endpoints."""

    def test_health_endpoint(self, client):
        response = client.get("/api/v1/intelligence/health")
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["data"]["status"] == "healthy"
        assert "capabilities" in data["data"]
        assert "meta" in data  # Envelope includes meta

    def test_classify_endpoint(self, client):
        response = client.post(
            "/api/v1/intelligence/classify",
            json={
                "message": "ERROR: java.lang.NullPointerException: null value",
                "log_group": "/aws/lambda/test",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        event = data["data"]["event"]
        assert event["severity"] == "ERROR"
        assert len(event["fingerprint"]) > 0

    def test_classify_with_pii_redaction(self, client):
        response = client.post(
            "/api/v1/intelligence/classify",
            json={
                "message": "User user@example.com failed login",
                "redact_pii": True,
            },
        )
        assert response.status_code == 200
        data = response.json()
        event = data["data"]["event"]
        assert "user@example.com" not in event["redacted_message"]

    def test_analyze_endpoint(self, client):
        response = client.post(
            "/api/v1/intelligence/analyze",
            json={
                "events": [
                    {"message": "ERROR: Database connection failed", "timestamp": "2024-01-01T10:00:00Z"},
                    {"message": "ERROR: Database connection failed", "timestamp": "2024-01-01T10:01:00Z"},
                    {"message": "INFO: Request completed", "timestamp": "2024-01-01T10:02:00Z"},
                ],
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        summary = data["data"]["summary"]
        assert summary["total_events_analyzed"] == 3
        assert summary["severity_distribution"]["error_count"] == 2

    def test_analyze_empty_events(self, client):
        response = client.post(
            "/api/v1/intelligence/analyze",
            json={"events": []},
        )
        # Should fail validation - min_length=1
        assert response.status_code == 422
