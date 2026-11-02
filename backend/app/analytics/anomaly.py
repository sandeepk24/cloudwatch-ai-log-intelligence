"""Statistical anomaly detection with configurable thresholds.

Design notes
------------
A statistical anomaly is just a data point that deviates from its recent
historical baseline by more than a configured number of standard
deviations (a z-score). That alone does **not** make it an incident:

- A single WARN-level blip that doubles for one minute is a statistical
  anomaly but rarely worth paging anyone.
- A sustained, high-magnitude deviation in ERROR-level traffic across
  multiple consecutive buckets is far more likely to represent a real
  incident.

We therefore separate two concepts everywhere in this module:

``classification`` (NORMAL / WATCH / ANOMALY)
    Purely statistical: how far is this point from its rolling baseline?

``is_incident`` (-> promotes classification to INCIDENT)
    A stricter judgement that additionally requires *all* of:
      1. The anomaly is driven by ERROR-level activity (not WARN/INFO), and
      2. The deviation persists for at least
         ``thresholds.min_consecutive_for_incident`` buckets in a row, and
      3. The observed count clears ``thresholds.min_absolute_count`` (a jump
         from 0 to 1 occurrence is never flagged, regardless of z-score).

Callers should surface ``classification`` for visibility but only alert /
page on ``is_incident``. Recurring WARN-level noise is tracked separately
(see `app.analytics.trends.find_recurring_warnings`) and is never promoted
to an incident by this module, however frequently it recurs.

No look-ahead bias
-------------------
``evaluate_series`` builds its baseline strictly from *preceding* buckets
(walk-forward). A bucket is only scored once at least
``min_history_points`` earlier buckets exist; earlier buckets are used
purely to build history and are not themselves scored. This keeps results
reproducible for backtesting against synthetic historical data and avoids
leaking "future" information into a baseline.

Robust baseline (outliers don't contaminate the baseline)
-----------------------------------------------------------
Once a bucket has been scored, its value is only folded into the rolling
baseline history if it was classified NORMAL. WATCH/ANOMALY/INCIDENT
values are deliberately excluded from future baselines. Without this, a
single large spike joining the history would immediately inflate the mean
and standard deviation enough to mask the *next* bucket of a genuinely
sustained incident -- which would make persistence-based incident
promotion (``min_consecutive_for_incident``) nearly impossible to ever
trigger. Excluding anomalous points keeps the baseline representing
"normal" operation for as long as the deviation persists.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from app.analytics.baseline import TimeBucket, mean_stddev
from app.analytics.severity import score_from_classification
from app.schemas.analytics import AnomalyClassification, AnomalyResult, AnomalyThresholds
from app.schemas.intelligence import LogSeverity


@dataclass
class PointEvaluation:
    """Result of evaluating a single observed value against history."""

    z_score: float | None
    baseline_mean: float
    baseline_stddev: float
    classification: AnomalyClassification
    explanation: list[str] = field(default_factory=list)


class AnomalyDetector:
    """z-score based anomaly detector over a rolling historical window."""

    def __init__(self, thresholds: AnomalyThresholds | None = None):
        self.thresholds = thresholds or AnomalyThresholds()

    def evaluate_point(self, observed: float, history: list[float]) -> PointEvaluation:
        """Evaluate a single observed value against a list of historical
        values. Returns NORMAL (with an explanatory note, not a crash) when
        there isn't enough history to compute a meaningful z-score.
        """
        t = self.thresholds
        explanation: list[str] = []

        if len(history) < t.min_history_points:
            explanation.append(
                f"Only {len(history)} historical data point(s) available; "
                f"{t.min_history_points} required for statistical comparison."
            )
            baseline_mean, _ = mean_stddev(history)
            return PointEvaluation(
                z_score=None,
                baseline_mean=baseline_mean,
                baseline_stddev=0.0,
                classification=AnomalyClassification.NORMAL,
                explanation=explanation,
            )

        mean, stddev = mean_stddev(history)

        if stddev == 0:
            # No variance in the baseline. Avoid division by zero: treat an
            # exact match as normal, and any deviation as at least WATCH
            # (never a bare ANOMALY, since we cannot quantify magnitude).
            if observed == mean:
                explanation.append("Observed value matches a zero-variance baseline exactly.")
                return PointEvaluation(None, mean, 0.0, AnomalyClassification.NORMAL, explanation)
            explanation.append(
                "Baseline has zero variance (perfectly flat history); any deviation is notable."
            )
            classification = (
                AnomalyClassification.WATCH
                if observed >= t.min_absolute_count
                else AnomalyClassification.NORMAL
            )
            return PointEvaluation(None, mean, 0.0, classification, explanation)

        z = (observed - mean) / stddev

        classification = AnomalyClassification.NORMAL
        if abs(z) >= t.z_score_anomaly and observed >= t.min_absolute_count:
            classification = AnomalyClassification.ANOMALY
            explanation.append(
                f"z-score {z:.2f} exceeds anomaly threshold {t.z_score_anomaly} "
                f"(observed={observed}, baseline_mean={mean:.2f}, baseline_stddev={stddev:.2f})"
            )
        elif abs(z) >= t.z_score_watch:
            classification = AnomalyClassification.WATCH
            explanation.append(
                f"z-score {z:.2f} exceeds watch threshold {t.z_score_watch} "
                f"(observed={observed}, baseline_mean={mean:.2f}, baseline_stddev={stddev:.2f})"
            )
        else:
            explanation.append(f"z-score {z:.2f} is within normal range")

        if observed < t.min_absolute_count and classification == AnomalyClassification.ANOMALY:
            # Defensive: the `and` clause above already guards this, kept
            # here in case thresholds are mutated between calls.
            classification = AnomalyClassification.WATCH
            explanation.append(
                f"Downgraded from ANOMALY to WATCH: observed count {observed} "
                f"below min_absolute_count {t.min_absolute_count}."
            )

        return PointEvaluation(z, mean, stddev, classification, explanation)

    def evaluate_series(
        self,
        buckets: list[TimeBucket],
        metric_name: str,
        value_fn: Callable[[TimeBucket], float],
        severity_fn: Callable[[TimeBucket], LogSeverity | None] | None = None,
    ) -> list[AnomalyResult]:
        """Evaluate a time-ordered list of buckets using a rolling baseline
        built strictly from preceding buckets (walk-forward, no look-ahead).

        Buckets without enough preceding history are silently skipped (not
        reported as NORMAL) -- callers can compare
        ``len(buckets) - len(result)`` against ``thresholds.min_history_points``
        to know how many leading buckets lacked sufficient history, and
        should surface AnalysisStatus.INSUFFICIENT_DATA when that gap
        consumes the entire requested window.
        """
        results: list[AnomalyResult] = []
        history: list[float] = []
        consecutive_streak = 0

        for bucket in buckets:
            observed = value_fn(bucket)

            if len(history) >= self.thresholds.min_history_points:
                evaluation = self.evaluate_point(observed, history)
                severity_hint = severity_fn(bucket) if severity_fn else None
                is_error_driven = severity_hint == LogSeverity.ERROR

                if evaluation.classification in (
                    AnomalyClassification.ANOMALY,
                    AnomalyClassification.WATCH,
                ):
                    consecutive_streak += 1
                else:
                    consecutive_streak = 0

                is_incident = (
                    evaluation.classification == AnomalyClassification.ANOMALY
                    and is_error_driven
                    and consecutive_streak >= self.thresholds.min_consecutive_for_incident
                )

                classification = evaluation.classification
                explanation = list(evaluation.explanation)
                if is_incident:
                    classification = AnomalyClassification.INCIDENT
                    explanation.append(
                        f"Promoted to INCIDENT: error-driven anomaly persisted for "
                        f"{consecutive_streak} consecutive bucket(s) "
                        f"(threshold={self.thresholds.min_consecutive_for_incident})."
                    )

                score, label = score_from_classification(classification, evaluation.z_score)

                results.append(
                    AnomalyResult(
                        metric_name=metric_name,
                        bucket_start=bucket.start,
                        bucket_end=bucket.end,
                        observed_value=observed,
                        baseline_mean=evaluation.baseline_mean,
                        baseline_stddev=evaluation.baseline_stddev,
                        z_score=evaluation.z_score,
                        classification=classification,
                        severity_score=score,
                        severity_label=label,
                        explanation=explanation,
                        is_incident=is_incident,
                    )
                )

                # Only fold NORMAL points back into the rolling baseline;
                # see the "Robust baseline" note in the module docstring.
                if evaluation.classification == AnomalyClassification.NORMAL:
                    history.append(observed)
            else:
                # Still building initial history -- nothing to compare
                # against yet, so every point counts.
                history.append(observed)

        return results
