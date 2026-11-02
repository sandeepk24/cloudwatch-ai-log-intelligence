"""CloudWatch Logs Insights-style pattern analysis and pattern diffing.

CloudWatch Logs Insights' `pattern` query command clusters log lines into
shapes server-side (returning fields like `@pattern`, `@sampleCount`,
`@severityLabel`). When that command is available and permitted,
`app.services.pattern_analysis` can use it directly. This module is the
*local* implementation of the same idea: it always works (mock mode, any
region, any permission set) and is what native results are normalized
into, so API consumers see one consistent shape regardless of
`data_source`.

CloudWatch Logs Insights has no literal `diff` query command; the
console's pattern "Compare" view -- and `diff_patterns` here -- works by
running pattern analysis over two separate windows and comparing the
resulting pattern sets. We replicate that behavior locally for both native
and local-statistical pattern sets.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Any

from app.analytics.severity import score_log_pattern
from app.intelligence.fingerprint import normalize_message
from app.schemas.analytics import LogPattern, PatternDiff
from app.schemas.intelligence import LogSeverity

DEFAULT_CHANGE_RATIO_THRESHOLD = 0.5


def pattern_hash(severity: str, normalized: str) -> str:
    """Stable identifier for a (severity, normalized-shape) pattern pair.
    Public so other pattern sources (e.g. parsed native CloudWatch `pattern`
    command output) can compute comparable IDs."""
    return hashlib.sha256(f"{severity}|{normalized}".encode()).hexdigest()[:16]


def coerce_severity(value: str | None) -> LogSeverity:
    """Best-effort coercion of a raw severity string to LogSeverity,
    defaulting to UNKNOWN rather than raising."""
    try:
        return LogSeverity(value)
    except ValueError:
        return LogSeverity.UNKNOWN


def extract_patterns(
    events: list[dict[str, Any]],
    *,
    min_occurrences: int = 1,
) -> list[LogPattern]:
    """Cluster events into patterns by normalized message shape + severity.

    Each event dict is expected to have: ``message`` (str), ``timestamp``
    (datetime), and optionally ``severity`` (str), ``log_group`` (str),
    ``ptr`` (str). Returns patterns sorted by occurrence count, descending.
    An empty input list returns an empty pattern list (not an error) --
    callers surface this as AnalysisStatus.INSUFFICIENT_DATA /
    `total_events == 0` rather than treating it as a failure.
    """
    if not events:
        return []

    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        message = event.get("message", "")
        severity = event.get("severity", LogSeverity.UNKNOWN.value)
        normalized = normalize_message(message)
        groups[(normalized, severity)].append(event)

    total = len(events)
    patterns: list[LogPattern] = []

    for (normalized, severity), group_events in groups.items():
        if len(group_events) < min_occurrences:
            continue

        timestamps = [e["timestamp"] for e in group_events]
        representative = group_events[0]

        patterns.append(
            LogPattern(
                pattern_id=pattern_hash(severity, normalized),
                normalized_pattern=normalized,
                severity=coerce_severity(severity),
                occurrence_count=len(group_events),
                ratio=len(group_events) / total,
                first_seen=min(timestamps),
                last_seen=max(timestamps),
                representative_message=representative.get("message", ""),
                sample_log_group=representative.get("log_group"),
                sample_ptr=representative.get("ptr"),
            )
        )

    patterns.sort(key=lambda p: p.occurrence_count, reverse=True)
    return patterns


def diff_patterns(
    current: list[LogPattern],
    baseline: list[LogPattern],
    *,
    change_ratio_threshold: float = DEFAULT_CHANGE_RATIO_THRESHOLD,
) -> PatternDiff:
    """Compare current-window patterns against a baseline window's patterns.

    - ``new_patterns``: present now, absent from the baseline entirely
      (marked ``is_new=True`` and re-scored accordingly)
    - ``disappeared_patterns``: present in baseline, absent now
    - ``increased_patterns`` / ``decreased_patterns``: present in both, with
      a relative ratio change at or beyond ``change_ratio_threshold``

    Callers are responsible for deciding what to do when ``baseline`` is
    empty (no historical data): this function will report every current
    pattern as "new", which is only meaningful when there really was a
    baseline window with zero matching events, not when no baseline could
    be fetched at all. See `app.services.pattern_analysis` for the explicit
    insufficient-data handling.
    """
    current_by_id = {p.pattern_id: p for p in current}
    baseline_by_id = {p.pattern_id: p for p in baseline}

    new_patterns: list[LogPattern] = []
    increased: list[LogPattern] = []
    decreased: list[LogPattern] = []

    for pid, pattern in current_by_id.items():
        if pid not in baseline_by_id:
            score, label = score_log_pattern(pattern, is_new=True, is_increasing=False)
            new_patterns.append(
                pattern.model_copy(update={"is_new": True, "severity_score": score, "severity_label": label})
            )
            continue

        base = baseline_by_id[pid]
        if base.ratio <= 0:
            continue
        relative_change = (pattern.ratio - base.ratio) / base.ratio

        if relative_change >= change_ratio_threshold:
            score, label = score_log_pattern(pattern, is_new=False, is_increasing=True)
            increased.append(pattern.model_copy(update={"severity_score": score, "severity_label": label}))
        elif relative_change <= -change_ratio_threshold:
            decreased.append(pattern)

    disappeared = [p for pid, p in baseline_by_id.items() if pid not in current_by_id]

    return PatternDiff(
        new_patterns=new_patterns,
        disappeared_patterns=disappeared,
        increased_patterns=increased,
        decreased_patterns=decreased,
        change_ratio_threshold=change_ratio_threshold,
    )
