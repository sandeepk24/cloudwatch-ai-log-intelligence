"""Configurable detection rules for log pattern recognition.

Rules are defined as dataclasses for easy serialization and testing.
Each rule specifies a pattern to match and metadata about what it detects.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from app.schemas.intelligence import LogSeverity, PatternCategory


class RuleType(StrEnum):
    """Type of pattern matching rule."""

    REGEX = "regex"
    KEYWORD = "keyword"
    STRUCTURED = "structured"
    COMPOSITE = "composite"


@dataclass
class DetectionRule:
    """A configurable rule for detecting log patterns."""

    id: str
    name: str
    description: str
    category: PatternCategory
    rule_type: RuleType
    pattern: str  # Regex pattern or keyword
    severity_override: LogSeverity | None = None
    confidence: float = 0.9
    enabled: bool = True
    false_positive_patterns: list[str] = field(default_factory=list)
    extract_fields: dict[str, str] = field(default_factory=dict)  # field_name -> regex group
    tags: list[str] = field(default_factory=list)

    _compiled_pattern: re.Pattern | None = field(default=None, repr=False)
    _compiled_fp_patterns: list[re.Pattern] = field(default_factory=list, repr=False)

    def __post_init__(self):
        """Compile regex patterns for performance."""
        if self.rule_type in (RuleType.REGEX, RuleType.COMPOSITE):
            self._compiled_pattern = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)
        self._compiled_fp_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.false_positive_patterns
        ]

    def matches(self, text: str) -> tuple[bool, dict[str, Any]]:
        """Check if the rule matches the text.

        Returns:
            Tuple of (matched, extracted_fields)
        """
        if not self.enabled:
            return False, {}

        extracted = {}

        if self.rule_type == RuleType.KEYWORD:
            if self.pattern.lower() not in text.lower():
                return False, {}
        elif self.rule_type in (RuleType.REGEX, RuleType.COMPOSITE):
            if self._compiled_pattern is None:
                return False, {}
            match = self._compiled_pattern.search(text)
            if not match:
                return False, {}
            # Extract named groups
            extracted = {k: v for k, v in match.groupdict().items() if v is not None}
        elif self.rule_type == RuleType.STRUCTURED:
            # Structured matching handled separately
            return False, {}

        return True, extracted

    def is_false_positive(self, text: str) -> tuple[bool, str | None]:
        """Check if the match is a false positive.

        Returns:
            Tuple of (is_false_positive, reason)
        """
        for i, fp_pattern in enumerate(self._compiled_fp_patterns):
            if fp_pattern.search(text):
                return True, self.false_positive_patterns[i]
        return False, None


# -----------------------------------------------------------------------------
# Default Detection Rules
# -----------------------------------------------------------------------------

DEFAULT_SEVERITY_RULES: list[DetectionRule] = [
    DetectionRule(
        id="severity_error",
        name="Error Level",
        description="Detect ERROR level logs",
        category=PatternCategory.UNKNOWN,
        rule_type=RuleType.REGEX,
        pattern=r"\b(ERROR|FATAL|CRITICAL|SEVERE|FAILURE|FAILED)\b",
        severity_override=LogSeverity.ERROR,
        confidence=0.95,
    ),
    DetectionRule(
        id="severity_warn",
        name="Warning Level",
        description="Detect WARN level logs",
        category=PatternCategory.UNKNOWN,
        rule_type=RuleType.REGEX,
        pattern=r"\b(WARN|WARNING|ALERT)\b",
        severity_override=LogSeverity.WARN,
        confidence=0.95,
    ),
    DetectionRule(
        id="severity_info",
        name="Info Level",
        description="Detect INFO level logs",
        category=PatternCategory.UNKNOWN,
        rule_type=RuleType.REGEX,
        pattern=r"\b(INFO|NOTICE)\b",
        severity_override=LogSeverity.INFO,
        confidence=0.9,
    ),
    DetectionRule(
        id="severity_debug",
        name="Debug Level",
        description="Detect DEBUG level logs",
        category=PatternCategory.UNKNOWN,
        rule_type=RuleType.REGEX,
        pattern=r"\b(DEBUG|TRACE|VERBOSE)\b",
        severity_override=LogSeverity.DEBUG,
        confidence=0.9,
    ),
]

DEFAULT_PATTERN_RULES: list[DetectionRule] = [
    # Java Exceptions
    DetectionRule(
        id="java_exception",
        name="Java Exception",
        description="Detect Java exception stack traces",
        category=PatternCategory.JAVA_EXCEPTION,
        rule_type=RuleType.REGEX,
        pattern=r"(?P<exception_type>[\w.]+(?:Exception|Error|Throwable))\s*:\s*(?P<message>[^\n]+)",
        confidence=0.95,
        extract_fields={"exception_type": "exception_type", "message": "message"},
    ),
    DetectionRule(
        id="java_stacktrace",
        name="Java Stack Trace",
        description="Detect Java at ... lines",
        category=PatternCategory.JAVA_EXCEPTION,
        rule_type=RuleType.REGEX,
        pattern=r"\bat\s+[\w.$]+\([\w.]+:\d+\)",
        confidence=0.9,
    ),
    DetectionRule(
        id="java_caused_by",
        name="Java Caused By",
        description="Detect Java caused by chains",
        category=PatternCategory.JAVA_EXCEPTION,
        rule_type=RuleType.REGEX,
        pattern=r"Caused by:\s*(?P<exception_type>[\w.]+(?:Exception|Error))\s*:\s*(?P<message>[^\n]+)",
        confidence=0.95,
    ),
    # Python Tracebacks
    DetectionRule(
        id="python_traceback",
        name="Python Traceback",
        description="Detect Python traceback",
        category=PatternCategory.PYTHON_TRACEBACK,
        rule_type=RuleType.REGEX,
        pattern=r"Traceback \(most recent call last\):",
        confidence=0.98,
    ),
    DetectionRule(
        id="python_exception",
        name="Python Exception",
        description="Detect Python exception line",
        category=PatternCategory.PYTHON_TRACEBACK,
        rule_type=RuleType.REGEX,
        pattern=r"(?P<exception_type>\w+(?:Error|Exception|Warning))\s*:\s*(?P<message>.+)",
        confidence=0.9,
        extract_fields={"exception_type": "exception_type", "message": "message"},
    ),
    DetectionRule(
        id="python_file_line",
        name="Python File Line",
        description="Detect Python File ... line ...",
        category=PatternCategory.PYTHON_TRACEBACK,
        rule_type=RuleType.REGEX,
        pattern=r'File "(?P<file>[^"]+)", line (?P<line>\d+)',
        confidence=0.9,
    ),
    # HTTP Errors
    DetectionRule(
        id="http_4xx",
        name="HTTP 4xx Error",
        description="Detect HTTP 4xx client errors",
        category=PatternCategory.HTTP_CLIENT_ERROR,
        rule_type=RuleType.REGEX,
        pattern=r"\b(?:HTTP[/ ]?)?(?P<status>4\d{2})\b",
        confidence=0.85,
        false_positive_patterns=[
            r"port\s*[=:]\s*4\d{2}",  # Port numbers
            r"pid\s*[=:]\s*4\d{2}",  # Process IDs
            r"\b4\d{2}\s*(?:ms|MB|KB|bytes)\b",  # Metrics
        ],
    ),
    DetectionRule(
        id="http_5xx",
        name="HTTP 5xx Error",
        description="Detect HTTP 5xx server errors",
        category=PatternCategory.HTTP_SERVER_ERROR,
        rule_type=RuleType.REGEX,
        pattern=r"\b(?:HTTP[/ ]?)?(?P<status>5\d{2})\b",
        confidence=0.9,
        false_positive_patterns=[
            r"port\s*[=:]\s*5\d{2}",
            r"pid\s*[=:]\s*5\d{2}",
            r"\b5\d{2}\s*(?:ms|MB|KB|bytes)\b",
        ],
    ),
    # Database Errors
    DetectionRule(
        id="db_connection_error",
        name="Database Connection Error",
        description="Detect database connection failures",
        category=PatternCategory.DATABASE_ERROR,
        rule_type=RuleType.REGEX,
        pattern=r"(?:cannot|could not|failed to|unable to)\s+(?:connect|establish|open)\s+(?:to\s+)?(?:database|db|mysql|postgres|mongodb|redis|dynamodb)",
        confidence=0.9,
    ),
    DetectionRule(
        id="db_query_error",
        name="Database Query Error",
        description="Detect database query failures",
        category=PatternCategory.DATABASE_ERROR,
        rule_type=RuleType.REGEX,
        pattern=r"(?:SQL|query|statement)\s*(?:error|exception|failed)|(?:deadlock|lock wait timeout)",
        confidence=0.85,
    ),
    DetectionRule(
        id="dynamodb_error",
        name="DynamoDB Error",
        description="Detect DynamoDB specific errors",
        category=PatternCategory.DATABASE_ERROR,
        rule_type=RuleType.REGEX,
        pattern=r"(?:ProvisionedThroughputExceededException|ConditionalCheckFailedException|ValidationException|ResourceNotFoundException)",
        confidence=0.95,
    ),
    # Connection/Timeout Errors
    DetectionRule(
        id="connection_timeout",
        name="Connection Timeout",
        description="Detect connection timeouts",
        category=PatternCategory.CONNECTION_TIMEOUT,
        rule_type=RuleType.REGEX,
        pattern=r"(?:connection|connect|read|write|socket|request)\s*(?:timed?\s*out|timeout)|timeout\s*(?:after|waiting|connecting|reading)",
        confidence=0.9,
    ),
    DetectionRule(
        id="connection_refused",
        name="Connection Refused",
        description="Detect connection refused errors",
        category=PatternCategory.CONNECTION_TIMEOUT,
        rule_type=RuleType.REGEX,
        pattern=r"connection\s+refused|ECONNREFUSED|ECONNRESET|ENOTFOUND|ETIMEDOUT",
        confidence=0.95,
    ),
    # Out of Memory
    DetectionRule(
        id="oom_java",
        name="Java OOM",
        description="Detect Java OutOfMemoryError",
        category=PatternCategory.OUT_OF_MEMORY,
        rule_type=RuleType.REGEX,
        pattern=r"(?:java\.lang\.)?OutOfMemoryError|(?:heap|metaspace|gc overhead)\s+(?:limit|space|exceeded)",
        confidence=0.98,
    ),
    DetectionRule(
        id="oom_generic",
        name="Generic OOM",
        description="Detect generic out of memory conditions",
        category=PatternCategory.OUT_OF_MEMORY,
        rule_type=RuleType.REGEX,
        pattern=r"out\s*of\s*memory|OOM\s*(?:killer|killed)|memory\s*(?:exhausted|exceeded|limit)",
        confidence=0.9,
    ),
    DetectionRule(
        id="oom_container",
        name="Container OOM",
        description="Detect container memory kills",
        category=PatternCategory.OUT_OF_MEMORY,
        rule_type=RuleType.REGEX,
        pattern=r"(?:container|pod|process)\s+(?:killed|terminated|OOMKilled)|exit\s*code\s*137",
        confidence=0.9,
    ),
    # Throttling
    DetectionRule(
        id="throttling_aws",
        name="AWS Throttling",
        description="Detect AWS throttling errors",
        category=PatternCategory.THROTTLING,
        rule_type=RuleType.REGEX,
        pattern=r"(?:Throttling|ThrottlingException|TooManyRequestsException|RequestLimitExceeded|Rate\s*exceeded|Slow\s*down)",
        confidence=0.95,
    ),
    DetectionRule(
        id="rate_limit",
        name="Rate Limit",
        description="Detect rate limiting",
        category=PatternCategory.RATE_LIMIT,
        rule_type=RuleType.REGEX,
        pattern=r"rate\s*limit(?:ed|ing)?|too\s*many\s*requests|429\s*(?:error|response)?|quota\s*exceeded",
        confidence=0.9,
    ),
    # Authentication/Authorization
    DetectionRule(
        id="auth_failure",
        name="Authentication Failure",
        description="Detect authentication failures",
        category=PatternCategory.AUTHENTICATION_FAILURE,
        rule_type=RuleType.REGEX,
        pattern=r"(?:authentication|auth|login|signin)\s*(?:failed|failure|error|denied)|invalid\s*(?:credentials|token|password|api.?key)|(?:401|Unauthorized)\b",
        confidence=0.9,
        false_positive_patterns=[
            r"authentication\s+successful",
            r"logged\s+in\s+successfully",
        ],
    ),
    DetectionRule(
        id="permission_denied",
        name="Permission Denied",
        description="Detect permission/authorization failures",
        category=PatternCategory.PERMISSION_DENIED,
        rule_type=RuleType.REGEX,
        pattern=r"(?:permission|access|authorization)\s*denied|(?:403|Forbidden)\b|AccessDeniedException|not\s*authorized",
        confidence=0.9,
        false_positive_patterns=[
            r"permission\s+granted",
            r"access\s+allowed",
        ],
    ),
    # Resource Errors
    DetectionRule(
        id="resource_not_found",
        name="Resource Not Found",
        description="Detect resource not found errors",
        category=PatternCategory.RESOURCE_NOT_FOUND,
        rule_type=RuleType.REGEX,
        pattern=r"(?:resource|file|object|entity|record)\s*(?:not\s*found|does\s*not\s*exist)|(?:404|NoSuchKey|NoSuchBucket)\b",
        confidence=0.85,
        false_positive_patterns=[
            r"creating\s+(?:if\s+)?not\s+found",
            r"or\s+create\s+if\s+not\s+found",
        ],
    ),
    # Circuit Breaker
    DetectionRule(
        id="circuit_breaker",
        name="Circuit Breaker",
        description="Detect circuit breaker events",
        category=PatternCategory.CIRCUIT_BREAKER,
        rule_type=RuleType.REGEX,
        pattern=r"circuit\s*breaker\s*(?:open|tripped|triggered|activated)|circuitbreaker.*(?:OPEN|HALF_OPEN)",
        confidence=0.95,
    ),
    # SSL/TLS Errors
    DetectionRule(
        id="ssl_error",
        name="SSL/TLS Error",
        description="Detect SSL/TLS certificate errors",
        category=PatternCategory.SSL_ERROR,
        rule_type=RuleType.REGEX,
        pattern=r"(?:SSL|TLS|certificate)\s*(?:error|failed|invalid|expired|verification\s*failed)|CERT_|SSLHandshakeException",
        confidence=0.9,
    ),
    # DNS Errors
    DetectionRule(
        id="dns_error",
        name="DNS Error",
        description="Detect DNS resolution failures",
        category=PatternCategory.DNS_ERROR,
        rule_type=RuleType.REGEX,
        pattern=r"(?:DNS|name\s*resolution|resolve)\s*(?:failed|error|timeout)|(?:NXDOMAIN|SERVFAIL|getaddrinfo\s*failed)",
        confidence=0.9,
    ),
    # Disk/Storage Errors
    DetectionRule(
        id="disk_full",
        name="Disk Full",
        description="Detect disk space issues",
        category=PatternCategory.DISK_FULL,
        rule_type=RuleType.REGEX,
        pattern=r"(?:disk|storage|volume)\s*(?:full|space\s*(?:exhausted|exceeded))|no\s*space\s*left|ENOSPC",
        confidence=0.95,
    ),
    # Validation Errors
    DetectionRule(
        id="validation_error",
        name="Validation Error",
        description="Detect input validation errors",
        category=PatternCategory.VALIDATION_ERROR,
        rule_type=RuleType.REGEX,
        pattern=r"validation\s*(?:failed|error)|invalid\s*(?:input|parameter|argument|request|format)",
        confidence=0.8,
        false_positive_patterns=[
            r"validation\s+passed",
            r"valid\s+input",
        ],
    ),
]


# -----------------------------------------------------------------------------
# Context Extraction Rules
# -----------------------------------------------------------------------------

CONTEXT_EXTRACTION_RULES: list[DetectionRule] = [
    DetectionRule(
        id="extract_request_id",
        name="Request ID",
        description="Extract request ID from logs",
        category=PatternCategory.UNKNOWN,
        rule_type=RuleType.REGEX,
        pattern=r"(?:request[-_]?id|req[-_]?id|x-request-id|x-amzn-requestid)\s*[=:]\s*['\"]?(?P<request_id>[a-f0-9-]{8,})['\"]?",
        confidence=0.95,
    ),
    DetectionRule(
        id="extract_trace_id",
        name="Trace ID",
        description="Extract trace ID (OpenTelemetry, X-Ray, etc.)",
        category=PatternCategory.UNKNOWN,
        rule_type=RuleType.REGEX,
        pattern=r"(?:trace[-_]?id|x-amzn-trace-id|traceid)\s*[=:]\s*['\"]?(?P<trace_id>[a-f0-9-]{16,})['\"]?",
        confidence=0.95,
    ),
    DetectionRule(
        id="extract_span_id",
        name="Span ID",
        description="Extract span ID",
        category=PatternCategory.UNKNOWN,
        rule_type=RuleType.REGEX,
        pattern=r"(?:span[-_]?id|spanid)\s*[=:]\s*['\"]?(?P<span_id>[a-f0-9-]{8,})['\"]?",
        confidence=0.9,
    ),
    DetectionRule(
        id="extract_correlation_id",
        name="Correlation ID",
        description="Extract correlation ID",
        category=PatternCategory.UNKNOWN,
        rule_type=RuleType.REGEX,
        pattern=r"(?:correlation[-_]?id|corr[-_]?id)\s*[=:]\s*['\"]?(?P<correlation_id>[a-f0-9-]{8,})['\"]?",
        confidence=0.9,
    ),
    DetectionRule(
        id="extract_service_name",
        name="Service Name",
        description="Extract service name",
        category=PatternCategory.UNKNOWN,
        rule_type=RuleType.REGEX,
        pattern=r"(?:service[-_]?name|service)\s*[=:]\s*['\"]?(?P<service_name>[a-zA-Z0-9_-]+)['\"]?",
        confidence=0.85,
    ),
    DetectionRule(
        id="extract_version",
        name="Version",
        description="Extract deployment version",
        category=PatternCategory.UNKNOWN,
        rule_type=RuleType.REGEX,
        pattern=r"(?:version|ver|v)\s*[=:]\s*['\"]?(?P<version>v?\d+\.\d+(?:\.\d+)?(?:[-+][a-zA-Z0-9.]+)?)['\"]?",
        confidence=0.85,
    ),
    DetectionRule(
        id="extract_environment",
        name="Environment",
        description="Extract environment name",
        category=PatternCategory.UNKNOWN,
        rule_type=RuleType.REGEX,
        pattern=r"(?:environment|env)\s*[=:]\s*['\"]?(?P<environment>prod(?:uction)?|stag(?:ing)?|dev(?:elopment)?|test|qa|uat)['\"]?",
        confidence=0.9,
    ),
    DetectionRule(
        id="extract_http_info",
        name="HTTP Info",
        description="Extract HTTP method, path, status",
        category=PatternCategory.UNKNOWN,
        rule_type=RuleType.REGEX,
        pattern=r"(?P<http_method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(?P<http_path>/[^\s]*)\s+(?:HTTP/\d\.\d\s+)?(?P<http_status>\d{3})",
        confidence=0.9,
    ),
    DetectionRule(
        id="extract_latency",
        name="Latency",
        description="Extract request latency",
        category=PatternCategory.UNKNOWN,
        rule_type=RuleType.REGEX,
        pattern=r"(?:latency|duration|elapsed|took|response[-_]?time)\s*[=:]\s*(?P<latency_ms>\d+(?:\.\d+)?)\s*(?:ms|milliseconds)?",
        confidence=0.85,
    ),
    DetectionRule(
        id="extract_error_code",
        name="Error Code",
        description="Extract error code",
        category=PatternCategory.UNKNOWN,
        rule_type=RuleType.REGEX,
        pattern=r"(?:error[-_]?code|err[-_]?code|code)\s*[=:]\s*['\"]?(?P<error_code>[A-Z_][A-Z0-9_]+)['\"]?",
        confidence=0.85,
    ),
]


def get_all_rules() -> list[DetectionRule]:
    """Get all default detection rules."""
    return DEFAULT_SEVERITY_RULES + DEFAULT_PATTERN_RULES + CONTEXT_EXTRACTION_RULES


def get_severity_rules() -> list[DetectionRule]:
    """Get severity detection rules."""
    return DEFAULT_SEVERITY_RULES


def get_pattern_rules() -> list[DetectionRule]:
    """Get pattern detection rules."""
    return DEFAULT_PATTERN_RULES


def get_context_rules() -> list[DetectionRule]:
    """Get context extraction rules."""
    return CONTEXT_EXTRACTION_RULES
