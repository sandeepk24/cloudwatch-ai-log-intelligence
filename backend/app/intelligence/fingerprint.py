"""Log event fingerprinting and deduplication.

Fingerprints normalize log messages by removing variable parts
(timestamps, IDs, numbers) to group similar events together.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

from app.schemas.intelligence import ClassifiedEvent, LogSeverity, PatternCategory

# Patterns for variable content to normalize
NORMALIZATION_PATTERNS = [
    # UUIDs
    (re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I), "<UUID>"),
    # Hex IDs (16+ chars)
    (re.compile(r"\b[0-9a-f]{16,}\b", re.I), "<HEX_ID>"),
    # Request/Trace IDs
    (re.compile(r"(?:request|trace|span|correlation)[_-]?id\s*[=:]\s*['\"]?[\w-]+['\"]?", re.I), "<ID>"),
    # Timestamps - ISO format
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<TIMESTAMP>"),
    # Timestamps - Unix epoch (ms or s)
    (re.compile(r"\b\d{10,13}\b"), "<EPOCH>"),
    # IP addresses
    (re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "<IP>"),
    # Ports
    (re.compile(r":(\d{2,5})\b"), ":<PORT>"),
    # Memory/size values
    (re.compile(r"\b\d+\s*(?:B|KB|MB|GB|TB|bytes)\b", re.I), "<SIZE>"),
    # Duration values
    (re.compile(r"\b\d+(?:\.\d+)?\s*(?:ms|s|sec|seconds?|minutes?|min|hours?|hr)\b", re.I), "<DURATION>"),
    # Generic numbers (last - catches remaining)
    (re.compile(r"\b\d{4,}\b"), "<NUM>"),
    # Version numbers
    (re.compile(r"v?\d+\.\d+(?:\.\d+)?(?:[-+]\w+)?"), "<VERSION>"),
    # Line numbers in stack traces
    (re.compile(r"(?:line\s+)\d+"), "line <N>"),
    (re.compile(r":\d+\)"), ":<N>)"),
    # Memory addresses
    (re.compile(r"0x[0-9a-f]+", re.I), "<ADDR>"),
    # Paths with variable components
    (re.compile(r"/[\w.-]+/[\w.-]+/[\w.-]+/"), "/<PATH>/"),
]

# Patterns for exception type extraction
EXCEPTION_PATTERNS = [
    re.compile(r"([\w.]+(?:Exception|Error|Fault|Failure))", re.I),
    re.compile(r"Caused by:\s*([\w.]+)", re.I),
]


@dataclass
class FingerprintResult:
    """Result of fingerprinting a log message."""

    fingerprint: str
    normalized_message: str
    exception_type: str | None = None
    is_stack_trace: bool = False


def normalize_message(message: str) -> str:
    """Normalize a message by replacing variable content with placeholders.

    Args:
        message: The original message

    Returns:
        Normalized message
    """
    result = message

    for pattern, replacement in NORMALIZATION_PATTERNS:
        result = pattern.sub(replacement, result)

    # Collapse whitespace
    result = re.sub(r"\s+", " ", result).strip()

    return result


def extract_exception_type(message: str) -> str | None:
    """Extract exception type from a message.

    Args:
        message: The log message

    Returns:
        Exception type name or None
    """
    for pattern in EXCEPTION_PATTERNS:
        match = pattern.search(message)
        if match:
            return match.group(1)
    return None


def is_stack_trace(message: str) -> bool:
    """Check if a message contains a stack trace.

    Args:
        message: The log message

    Returns:
        True if message contains stack trace
    """
    # Java stack trace
    if re.search(r"\bat\s+[\w.$]+\([\w.]+:\d+\)", message):
        return True
    # Python traceback
    if "Traceback (most recent call last):" in message:
        return True
    if re.search(r'File "[^"]+", line \d+', message):
        return True
    # .NET stack trace
    return bool(re.search(r"at [\w.]+\([^)]*\) in [^:]+:line \d+", message))


def compute_fingerprint(
    message: str,
    severity: LogSeverity | None = None,
    category: PatternCategory | None = None,
    log_group: str | None = None,
) -> FingerprintResult:
    """Compute a fingerprint for a log message.

    The fingerprint is used to group similar log events together.
    It normalizes variable content and hashes the result.

    Args:
        message: The log message
        severity: Optional severity to include
        category: Optional pattern category to include
        log_group: Optional log group to include

    Returns:
        FingerprintResult with fingerprint and metadata
    """
    normalized = normalize_message(message)
    exception_type = extract_exception_type(message)
    has_stack_trace = is_stack_trace(message)

    # Build fingerprint components
    components = []

    if severity:
        components.append(f"severity:{severity.value}")

    if category and category != PatternCategory.UNKNOWN:
        components.append(f"category:{category.value}")

    if exception_type:
        components.append(f"exception:{exception_type}")

    if log_group:
        # Use log group prefix (first 2-3 segments) to avoid over-specificity
        parts = log_group.strip("/").split("/")
        group_prefix = "/".join(parts[:min(3, len(parts))])
        components.append(f"group:{group_prefix}")

    components.append(f"msg:{normalized}")

    # Create hash
    fingerprint_input = "|".join(components)
    fingerprint = hashlib.sha256(fingerprint_input.encode()).hexdigest()[:16]

    return FingerprintResult(
        fingerprint=fingerprint,
        normalized_message=normalized,
        exception_type=exception_type,
        is_stack_trace=has_stack_trace,
    )


class EventDeduplicator:
    """Deduplicate log events using fingerprints."""

    def __init__(self):
        """Initialize the deduplicator."""
        self._fingerprint_counts: dict[str, int] = {}
        self._fingerprint_first_event: dict[str, ClassifiedEvent] = {}
        self._fingerprint_last_event: dict[str, ClassifiedEvent] = {}
        self._fingerprint_samples: dict[str, list[ClassifiedEvent]] = {}

    def add_event(self, event: ClassifiedEvent, max_samples: int = 5) -> bool:
        """Add an event to the deduplicator.

        Args:
            event: The classified event
            max_samples: Maximum sample events to keep per fingerprint

        Returns:
            True if this is a new fingerprint, False if duplicate
        """
        fp = event.fingerprint
        is_new = fp not in self._fingerprint_counts

        self._fingerprint_counts[fp] = self._fingerprint_counts.get(fp, 0) + 1

        if is_new:
            self._fingerprint_first_event[fp] = event
            self._fingerprint_samples[fp] = [event]

        self._fingerprint_last_event[fp] = event

        # Keep sample events
        if not is_new and fp in self._fingerprint_samples:
            samples = self._fingerprint_samples[fp]
            if len(samples) < max_samples:
                samples.append(event)

        return is_new

    def get_unique_events(self) -> list[ClassifiedEvent]:
        """Get one representative event per fingerprint.

        Returns:
            List of representative events
        """
        return list(self._fingerprint_first_event.values())

    def get_occurrence_count(self, fingerprint: str) -> int:
        """Get the occurrence count for a fingerprint.

        Args:
            fingerprint: The fingerprint

        Returns:
            Number of occurrences
        """
        return self._fingerprint_counts.get(fingerprint, 0)

    def get_samples(self, fingerprint: str) -> list[ClassifiedEvent]:
        """Get sample events for a fingerprint.

        Args:
            fingerprint: The fingerprint

        Returns:
            List of sample events
        """
        return self._fingerprint_samples.get(fingerprint, [])

    def get_first_seen(self, fingerprint: str) -> ClassifiedEvent | None:
        """Get the first event for a fingerprint.

        Args:
            fingerprint: The fingerprint

        Returns:
            First event or None
        """
        return self._fingerprint_first_event.get(fingerprint)

    def get_last_seen(self, fingerprint: str) -> ClassifiedEvent | None:
        """Get the last event for a fingerprint.

        Args:
            fingerprint: The fingerprint

        Returns:
            Last event or None
        """
        return self._fingerprint_last_event.get(fingerprint)

    def get_stats(self) -> dict[str, Any]:
        """Get deduplication statistics.

        Returns:
            Dictionary with stats
        """
        total_events = sum(self._fingerprint_counts.values())
        unique_events = len(self._fingerprint_counts)

        return {
            "total_events": total_events,
            "unique_events": unique_events,
            "deduplication_ratio": (
                1 - (unique_events / total_events) if total_events > 0 else 0
            ),
            "top_fingerprints": sorted(
                [
                    {"fingerprint": fp, "count": count}
                    for fp, count in self._fingerprint_counts.items()
                ],
                key=lambda x: x["count"],
                reverse=True,
            )[:10],
        }

    def clear(self) -> None:
        """Clear all state."""
        self._fingerprint_counts.clear()
        self._fingerprint_first_event.clear()
        self._fingerprint_last_event.clear()
        self._fingerprint_samples.clear()
