"""Severity scoring for detected anomalies and patterns.

Scoring criteria (documented)
------------------------------
Every score is built from a small set of transparent, independently
reasoned factors so a human can always explain *why* something scored the
way it did, rather than treating it as a black box.

**Anomaly scoring** (`score_from_classification`):

  classification baseline points:
    NORMAL=0, WATCH=15, ANOMALY=40, INCIDENT=55

  + magnitude bonus, from |z-score|:
    |z| >= 5.0  -> +25
    |z| >= 3.0  -> +15
    |z| >= 2.0  -> +8
    otherwise   -> +0

**Pattern scoring** (`score_log_pattern`), used for newly-appearing or
frequency-changing log patterns:

  event severity baseline points:
    ERROR=40, WARN=20, INFO/DEBUG/TRACE/UNKNOWN=5

  + newly appearing vs. baseline window: +25
  + increasing frequency vs. baseline:   +15
  + occurrence ratio within the window:
      ratio >= 0.30 -> +20
      ratio >= 0.10 -> +10
      otherwise     -> +0

Both scores are clamped to [0, 100] and mapped to a label:

  0-24   -> low
  25-49  -> medium
  50-74  -> high
  75-100 -> critical

These weights are intentionally simple linear additions (not a trained
model) so they can be reasoned about, audited, and tuned by operators.
"""

from __future__ import annotations

from app.schemas.analytics import AnomalyClassification, LogPattern, SeverityLabel
from app.schemas.intelligence import LogSeverity

_CLASSIFICATION_POINTS: dict[AnomalyClassification, float] = {
    AnomalyClassification.NORMAL: 0.0,
    AnomalyClassification.WATCH: 15.0,
    AnomalyClassification.ANOMALY: 40.0,
    AnomalyClassification.INCIDENT: 55.0,
}

_EVENT_SEVERITY_POINTS: dict[LogSeverity, float] = {
    LogSeverity.ERROR: 40.0,
    LogSeverity.WARN: 20.0,
}


def label_for_score(score: float) -> SeverityLabel:
    """Map a 0-100 score to a human-facing label."""
    if score >= 75:
        return SeverityLabel.CRITICAL
    if score >= 50:
        return SeverityLabel.HIGH
    if score >= 25:
        return SeverityLabel.MEDIUM
    return SeverityLabel.LOW


def _magnitude_bonus(z_score: float | None) -> float:
    if z_score is None:
        return 0.0
    magnitude = abs(z_score)
    if magnitude == float("inf"):
        return 25.0
    if magnitude >= 5.0:
        return 25.0
    if magnitude >= 3.0:
        return 15.0
    if magnitude >= 2.0:
        return 8.0
    return 0.0


def score_from_classification(
    classification: AnomalyClassification,
    z_score: float | None,
) -> tuple[float, SeverityLabel]:
    """Score a statistical anomaly result. See module docstring for the
    documented criteria."""
    score = _CLASSIFICATION_POINTS.get(classification, 0.0)
    score += _magnitude_bonus(z_score)
    score = min(score, 100.0)
    return score, label_for_score(score)


def score_log_pattern(
    pattern: LogPattern,
    *,
    is_new: bool,
    is_increasing: bool,
) -> tuple[float, SeverityLabel]:
    """Score a discovered/changed log pattern. See module docstring for the
    documented criteria."""
    score = _EVENT_SEVERITY_POINTS.get(pattern.severity, 5.0)

    if is_new:
        score += 25.0
    if is_increasing:
        score += 15.0

    if pattern.ratio >= 0.30:
        score += 20.0
    elif pattern.ratio >= 0.10:
        score += 10.0

    score = min(score, 100.0)
    return score, label_for_score(score)
