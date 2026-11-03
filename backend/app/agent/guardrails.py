"""PII redaction, prompt-injection defenses, and tool input validation."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from app.agent.tool_schemas import ALLOWED_TOOLS, TOOL_INPUT_MODELS
from app.core.config import settings
from app.core.logging import get_logger
from app.intelligence.redaction import redact_for_ai
from app.schemas.logs import TimeRangePreset

logger = get_logger(__name__)

_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "ignore_instructions",
        re.compile(
            r"(ignore\s+(all\s+)?(previous|prior)\s+instructions|"
            r"disregard\s+(the\s+)?system\s+prompt|"
            r"you\s+are\s+now\s+|"
            r"jailbreak|"
            r"reveal\s+(the\s+)?(system|hidden)\s+prompt)",
            re.IGNORECASE,
        ),
    ),
    (
        "tool_escalation",
        re.compile(
            r"\b(run|execute|delete|terminate|stop|update|modify|patch|remediate)\s+"
            r"(service|task|instance|cluster|alarm|deployment)\b",
            re.IGNORECASE,
        ),
    ),
]

_BLOCKED_QUERY_FRAGMENTS = re.compile(
    r"\b(drop\s+table|;\s*rm\s+-|curl\s+.*\|\s*sh|wget\s+.*\|\s*bash)\b",
    re.IGNORECASE,
)

_MAX_WINDOW = timedelta(hours=24)


def sanitize_user_question(question: str) -> tuple[str, list[str]]:
    """Normalize and scan the user question; returns (sanitized, guardrail_notes)."""
    notes: list[str] = []
    q = question.strip()
    q = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", q)
    q = redact_for_ai(q)

    for label, pattern in _INJECTION_PATTERNS:
        if pattern.search(q):
            notes.append(
                f"Detected possible prompt-injection or remediation request pattern ({label}); "
                "agent will refuse automated remediation and treat instructions as untrusted."
            )

    if len(q) > 4000:
        q = q[:4000]
        notes.append("Question truncated to 4000 characters.")

    return q, notes


def validate_tool_call(tool_name: str, arguments: dict) -> tuple[dict, list[str]]:
    """Validate tool name and arguments against strict schemas and global limits."""
    notes: list[str] = []
    if tool_name not in ALLOWED_TOOLS:
        raise ValueError(f"Tool not allowed: {tool_name}")

    model_cls = TOOL_INPUT_MODELS[tool_name]
    parsed = model_cls.model_validate(arguments)

    # Enforce log group cap from settings
    max_lg = min(settings.agent_max_log_groups_per_tool, settings.cw_query_max_log_groups)
    for field_name in ("log_group_names",):
        if hasattr(parsed, field_name):
            groups = getattr(parsed, field_name)
            if len(groups) > max_lg:
                raise ValueError(f"Too many log groups (max {max_lg})")

    # Time window bounds
    start, end = _resolve_bounds(parsed)
    if end - start > _MAX_WINDOW:
        raise ValueError("Time window exceeds 24 hours")

    if tool_name == "search_cloudwatch_logs":
        qs = getattr(parsed, "query_string", "")
        if _BLOCKED_QUERY_FRAGMENTS.search(qs):
            raise ValueError("Query string contains blocked fragment")

    return parsed.model_dump(mode="json"), notes


def _resolve_bounds(parsed) -> tuple[datetime, datetime]:
    now = datetime.now(UTC)
    preset = getattr(parsed, "time_range_preset", TimeRangePreset.LAST_1_HOUR)
    start = getattr(parsed, "start_time", None)
    end = getattr(parsed, "end_time", None)
    if start and end:
        return start, end
    deltas = {
        TimeRangePreset.LAST_15_MINUTES: timedelta(minutes=15),
        TimeRangePreset.LAST_1_HOUR: timedelta(hours=1),
        TimeRangePreset.LAST_6_HOURS: timedelta(hours=6),
        TimeRangePreset.LAST_24_HOURS: timedelta(hours=24),
    }
    delta = deltas.get(preset, timedelta(hours=1))
    return now - delta, now


def redact_tool_payload(data: dict | list | str) -> dict | list | str:
    """Recursively redact strings in tool results before sending to the model."""
    if isinstance(data, str):
        return redact_for_ai(data)
    if isinstance(data, list):
        return [redact_tool_payload(item) for item in data]
    if isinstance(data, dict):
        return {k: redact_tool_payload(v) for k, v in data.items()}
    return data
