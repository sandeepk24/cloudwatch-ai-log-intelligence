"""Deployment boundary analysis — before-vs-after error rate comparison.

Identifies deployment events, then computes whether error rates increased
materially after the deploy compared to a baseline window before it.

Confidence criteria (explicit, not LLM-generated):
  STRONG      error_rate_change_ratio ≥ 5  AND after_error_count ≥ 5
  MODERATE    error_rate_change_ratio ≥ 2  AND after_error_count ≥ 2
  WEAK        error_rate_change_ratio > 1  AND after_error_count ≥ 1
  SPECULATIVE insufficient data in before or after window
"""

from __future__ import annotations

from datetime import timedelta

from app.core.logging import get_logger
from app.schemas.incidents import (
    DeploymentDelta,
    DeploymentEvent,
    EvidenceStrength,
    RawSignal,
    SignalKind,
    SignalSeverity,
)
from .signals import is_deployment_signal

logger = get_logger(__name__)

ERROR_SEVERITIES = frozenset({SignalSeverity.HIGH, SignalSeverity.CRITICAL, SignalSeverity.MEDIUM})


def extract_deployment_events(signals: list[RawSignal]) -> list[DeploymentEvent]:
    """Identify deployment signals and return structured DeploymentEvent objects."""
    events: list[DeploymentEvent] = []
    for sig in signals:
        if is_deployment_signal(sig.kind, sig.message):
            version = sig.deployment_version or _extract_version_from_message(sig.message)
            events.append(
                DeploymentEvent(
                    service_name=sig.service_name,
                    version=version or "unknown",
                    deployed_at=sig.timestamp,
                    signal_id=sig.signal_id,
                )
            )
    # Sort by time; deduplicate same (service, version) within 5 minutes
    events.sort(key=lambda e: e.deployed_at)
    return _deduplicate_deployments(events)


def _deduplicate_deployments(events: list[DeploymentEvent]) -> list[DeploymentEvent]:
    """Remove duplicate deployment events for the same (service, version) within 5 min."""
    result: list[DeploymentEvent] = []
    seen: list[DeploymentEvent] = []
    for ev in events:
        duplicate = False
        for prev in seen:
            if (
                prev.service_name == ev.service_name
                and prev.version == ev.version
                and abs((ev.deployed_at - prev.deployed_at).total_seconds()) < 300
            ):
                duplicate = True
                break
        if not duplicate:
            result.append(ev)
            seen.append(ev)
    return result


def compute_deployment_deltas(
    signals: list[RawSignal],
    deployments: list[DeploymentEvent],
    before_window_minutes: int = 30,
    after_window_minutes: int = 30,
) -> list[DeploymentDelta]:
    """Compute before/after error rate delta for each deployment event."""
    deltas: list[DeploymentDelta] = []

    for deploy in deployments:
        before_start = deploy.deployed_at - timedelta(minutes=before_window_minutes)
        after_end = deploy.deployed_at + timedelta(minutes=after_window_minutes)

        before_errors = [
            s
            for s in signals
            if s.service_name == deploy.service_name
            and s.severity in ERROR_SEVERITIES
            and before_start <= s.timestamp < deploy.deployed_at
        ]
        after_errors = [
            s
            for s in signals
            if s.service_name == deploy.service_name
            and s.severity in ERROR_SEVERITIES
            and deploy.deployed_at <= s.timestamp <= after_end
        ]

        before_rate = len(before_errors) / before_window_minutes
        after_rate = len(after_errors) / after_window_minutes

        # Compute ratio; handle zero baseline (treat as large ratio if after > 0)
        if before_rate > 0:
            ratio: float | None = after_rate / before_rate
        elif after_rate > 0:
            ratio = None  # infinite — clean baseline, errors appeared after deploy
        else:
            ratio = 1.0  # both zero, no change

        absolute_increase = len(after_errors) - len(before_errors)
        is_regression = (ratio is None and len(after_errors) >= 1) or (
            ratio is not None and ratio > 1.0 and len(after_errors) >= 1
        )

        confidence, rationale = _score_regression_confidence(
            ratio=ratio,
            after_count=len(after_errors),
            before_count=len(before_errors),
        )

        deltas.append(
            DeploymentDelta(
                deployment=deploy,
                service_name=deploy.service_name,
                before_window_minutes=before_window_minutes,
                before_error_count=len(before_errors),
                before_error_rate_per_minute=before_rate,
                before_signal_ids=[s.signal_id for s in before_errors],
                after_window_minutes=after_window_minutes,
                after_error_count=len(after_errors),
                after_error_rate_per_minute=after_rate,
                after_signal_ids=[s.signal_id for s in after_errors],
                error_rate_change_ratio=ratio,
                error_increase_absolute=max(0, absolute_increase),
                is_regression=is_regression,
                regression_confidence=confidence,
                regression_rationale=rationale,
            )
        )

    return deltas


def _score_regression_confidence(
    ratio: float | None,
    after_count: int,
    before_count: int,
) -> tuple[EvidenceStrength, str]:
    """Map regression metrics to an EvidenceStrength with an explicit rationale."""

    if ratio is None:
        # Clean baseline, errors appeared after deploy
        if after_count >= 5:
            return (
                EvidenceStrength.STRONG,
                f"Zero errors before deployment; {after_count} errors after — "
                "clean baseline makes regression highly likely.",
            )
        if after_count >= 2:
            return (
                EvidenceStrength.MODERATE,
                f"Zero errors before deployment; {after_count} errors after — "
                "clean baseline supports regression.",
            )
        if after_count >= 1:
            return (
                EvidenceStrength.WEAK,
                f"Zero errors before deployment; {after_count} error(s) after — "
                "possible regression but sample size is small.",
            )
        return (
            EvidenceStrength.SPECULATIVE,
            "No errors before or after deployment — insufficient data.",
        )

    if ratio >= 5 and after_count >= 5:
        return (
            EvidenceStrength.STRONG,
            f"Error rate increased {ratio:.1f}× after deployment "
            f"(before={before_count}, after={after_count}).",
        )
    if ratio >= 2 and after_count >= 2:
        return (
            EvidenceStrength.MODERATE,
            f"Error rate increased {ratio:.1f}× after deployment "
            f"(before={before_count}, after={after_count}).",
        )
    if ratio > 1 and after_count >= 1:
        return (
            EvidenceStrength.WEAK,
            f"Error rate increased {ratio:.1f}× after deployment "
            f"(before={before_count}, after={after_count}) — small sample.",
        )
    return (
        EvidenceStrength.SPECULATIVE,
        f"No meaningful error rate change (ratio={ratio:.2f}, "
        f"before={before_count}, after={after_count}).",
    )


def _extract_version_from_message(message: str) -> str | None:
    """Try to extract a version string from a deployment message."""
    import re

    # Match "v1.2.3", "v1.23", version=1.2.3, tag:1.2.3
    patterns = [
        r"\b(v\d+\.\d+\.\d+(?:-[\w.]+)?)\b",
        r"version[=:\s]+([^\s,]+)",
        r"tag[=:\s]+([^\s,]+)",
        r"image[=:\s]+[^\s:]+:([^\s,]+)",
    ]
    for pat in patterns:
        m = re.search(pat, message, re.IGNORECASE)
        if m:
            return m.group(1)
    return None
