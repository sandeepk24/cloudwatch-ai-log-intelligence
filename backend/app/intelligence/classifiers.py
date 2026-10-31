"""Log severity classification and structured field recognition."""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any, ClassVar

from app.schemas.intelligence import (
    DetectedPattern,
    ExtractedContext,
    LogSeverity,
    PatternCategory,
)

from .rules import (
    CONTEXT_EXTRACTION_RULES,
    DEFAULT_PATTERN_RULES,
    DEFAULT_SEVERITY_RULES,
    DetectionRule,
)


class SeverityClassifier:
    """Classify log messages by severity level."""

    def __init__(self, rules: list[DetectionRule] | None = None):
        """Initialize the classifier.

        Args:
            rules: Custom severity rules, or use defaults
        """
        self._rules = rules or DEFAULT_SEVERITY_RULES

    def classify(self, message: str, raw_fields: dict[str, Any] | None = None) -> LogSeverity:
        """Classify the severity of a log message.

        Args:
            message: The log message
            raw_fields: Optional structured fields from the log

        Returns:
            The detected severity level
        """
        # First, check structured fields for explicit level
        if raw_fields:
            for level_key in ("level", "severity", "log_level", "loglevel", "@level"):
                if level_key in raw_fields:
                    level_value = str(raw_fields[level_key]).upper()
                    try:
                        return LogSeverity(level_value)
                    except ValueError:
                        # Map common variations
                        level_map = {
                            "ERR": LogSeverity.ERROR,
                            "FATAL": LogSeverity.ERROR,
                            "CRITICAL": LogSeverity.ERROR,
                            "SEVERE": LogSeverity.ERROR,
                            "WARNING": LogSeverity.WARN,
                            "INFORMATION": LogSeverity.INFO,
                            "INFORMATIONAL": LogSeverity.INFO,
                            "VERBOSE": LogSeverity.DEBUG,
                            "TRACE": LogSeverity.TRACE,
                        }
                        if level_value in level_map:
                            return level_map[level_value]

        # Apply rules to message content
        for rule in self._rules:
            matched, _ = rule.matches(message)
            if matched and rule.severity_override:
                return rule.severity_override

        return LogSeverity.UNKNOWN


class PatternDetector:
    """Detect patterns in log messages."""

    def __init__(self, rules: list[DetectionRule] | None = None):
        """Initialize the detector.

        Args:
            rules: Custom pattern rules, or use defaults
        """
        self._rules = rules or DEFAULT_PATTERN_RULES

    def detect(self, message: str) -> list[DetectedPattern]:
        """Detect patterns in a log message.

        Args:
            message: The log message

        Returns:
            List of detected patterns
        """
        patterns: list[DetectedPattern] = []

        for rule in self._rules:
            matched, extracted = rule.matches(message)
            if not matched:
                continue

            is_fp, fp_reason = rule.is_false_positive(message)

            pattern = DetectedPattern(
                category=rule.category,
                confidence=rule.confidence,
                matched_rule=rule.id,
                matched_text=extracted.get("message") or extracted.get("exception_type"),
                is_false_positive=is_fp,
                false_positive_reason=fp_reason,
            )
            patterns.append(pattern)

        return patterns


class ContextExtractor:
    """Extract context information from log messages."""

    # Common JSON log formats
    JSON_PATTERNS: ClassVar[list[re.Pattern]] = [
        re.compile(r"^\s*\{.*\}\s*$", re.DOTALL),  # Full JSON
        re.compile(r"\{[^{}]+\}"),  # Embedded JSON
    ]

    def __init__(self, rules: list[DetectionRule] | None = None):
        """Initialize the extractor.

        Args:
            rules: Custom extraction rules, or use defaults
        """
        self._rules = rules or CONTEXT_EXTRACTION_RULES

    def extract(
        self, message: str, raw_fields: dict[str, Any] | None = None
    ) -> ExtractedContext:
        """Extract context from a log message.

        Args:
            message: The log message
            raw_fields: Optional structured fields

        Returns:
            Extracted context
        """
        context = ExtractedContext()
        extra: dict[str, Any] = {}

        # Extract from raw fields first (higher priority)
        if raw_fields:
            self._extract_from_fields(raw_fields, context, extra)

        # Try to parse JSON from message
        self._extract_from_json(message, context, extra)

        # Apply regex rules to message
        self._apply_extraction_rules(message, context)

        # Set extra fields
        if extra:
            context.extra = extra

        return context

    def _extract_from_fields(
        self,
        fields: dict[str, Any],
        context: ExtractedContext,
        extra: dict[str, Any],
    ) -> None:
        """Extract context from structured fields."""
        field_mappings = {
            # Request/Trace IDs
            ("request_id", "requestId", "req_id", "reqId", "x-request-id"): "request_id",
            ("trace_id", "traceId", "x-amzn-trace-id"): "trace_id",
            ("span_id", "spanId"): "span_id",
            ("correlation_id", "correlationId", "corr_id"): "correlation_id",
            # Service info
            ("service", "service_name", "serviceName"): "service_name",
            ("version", "ver", "app_version", "appVersion"): "deployment_version",
            ("environment", "env"): "environment",
            # Infrastructure
            ("hostname", "host"): "hostname",
            ("pod", "pod_name", "podName", "kubernetes.pod.name"): "pod_name",
            ("container_id", "containerId"): "container_id",
            # Request info
            ("method", "http_method", "httpMethod"): "http_method",
            ("path", "http_path", "httpPath", "url", "uri"): "http_path",
            ("status", "status_code", "statusCode", "http_status"): "http_status",
            ("latency", "latency_ms", "duration", "duration_ms", "response_time"): "latency_ms",
            # Error info
            ("error_code", "errorCode", "code"): "error_code",
        }

        for field_names, attr_name in field_mappings.items():
            for field_name in field_names:
                if field_name in fields:
                    value = fields[field_name]
                    if value is not None:
                        if attr_name in ("http_status", "latency_ms"):
                            try:
                                value = int(value) if attr_name == "http_status" else float(value)
                            except (ValueError, TypeError):
                                continue
                        setattr(context, attr_name, value)
                    break

        # Put unmapped fields in extra
        mapped_fields = set()
        for field_names, _ in field_mappings.items():
            mapped_fields.update(field_names)

        for key, value in fields.items():
            if key not in mapped_fields and not key.startswith("@"):
                extra[key] = value

    def _extract_from_json(
        self,
        message: str,
        context: ExtractedContext,
        extra: dict[str, Any],
    ) -> None:
        """Extract context from JSON in message."""
        for pattern in self.JSON_PATTERNS:
            match = pattern.search(message)
            if match:
                try:
                    data = json.loads(match.group())
                    if isinstance(data, dict):
                        self._extract_from_fields(data, context, extra)
                        return
                except json.JSONDecodeError:
                    continue

    def _apply_extraction_rules(self, message: str, context: ExtractedContext) -> None:
        """Apply regex extraction rules to message."""
        for rule in self._rules:
            matched, extracted = rule.matches(message)
            if matched:
                for field_name, value in extracted.items():
                    if hasattr(context, field_name) and getattr(context, field_name) is None:
                        # Handle type conversion for numeric fields
                        if field_name in ("http_status",):
                            try:
                                value = int(value)
                            except (ValueError, TypeError):
                                continue
                        elif field_name in ("latency_ms",):
                            try:
                                value = float(value)
                            except (ValueError, TypeError):
                                continue
                        setattr(context, field_name, value)


class LogClassifier:
    """Combined log classifier with severity, patterns, and context extraction."""

    def __init__(
        self,
        severity_rules: list[DetectionRule] | None = None,
        pattern_rules: list[DetectionRule] | None = None,
        context_rules: list[DetectionRule] | None = None,
    ):
        """Initialize the classifier.

        Args:
            severity_rules: Custom severity rules
            pattern_rules: Custom pattern rules
            context_rules: Custom context extraction rules
        """
        self._severity_classifier = SeverityClassifier(severity_rules)
        self._pattern_detector = PatternDetector(pattern_rules)
        self._context_extractor = ContextExtractor(context_rules)

    def classify(
        self,
        message: str,
        timestamp: datetime | None = None,
        log_group: str = "",
        log_stream: str | None = None,
        raw_fields: dict[str, Any] | None = None,
    ) -> tuple[LogSeverity, list[DetectedPattern], ExtractedContext]:
        """Classify a log message.

        Args:
            message: The log message
            timestamp: Event timestamp
            log_group: Source log group
            log_stream: Source log stream
            raw_fields: Optional structured fields

        Returns:
            Tuple of (severity, patterns, context)
        """
        severity = self._severity_classifier.classify(message, raw_fields)
        patterns = self._pattern_detector.detect(message)
        context = self._context_extractor.extract(message, raw_fields)

        # Elevate severity based on detected patterns
        if severity in (LogSeverity.INFO, LogSeverity.DEBUG, LogSeverity.UNKNOWN):
            for pattern in patterns:
                if pattern.is_false_positive:
                    continue
                if pattern.category in (
                    PatternCategory.JAVA_EXCEPTION,
                    PatternCategory.PYTHON_TRACEBACK,
                    PatternCategory.HTTP_SERVER_ERROR,
                    PatternCategory.DATABASE_ERROR,
                    PatternCategory.OUT_OF_MEMORY,
                    PatternCategory.SSL_ERROR,
                    PatternCategory.DNS_ERROR,
                ):
                    severity = LogSeverity.ERROR
                    break
                if pattern.category in (
                    PatternCategory.HTTP_CLIENT_ERROR,
                    PatternCategory.THROTTLING,
                    PatternCategory.RATE_LIMIT,
                    PatternCategory.CONNECTION_TIMEOUT,
                    PatternCategory.CIRCUIT_BREAKER,
                ):
                    severity = LogSeverity.WARN
                    break

        return severity, patterns, context
