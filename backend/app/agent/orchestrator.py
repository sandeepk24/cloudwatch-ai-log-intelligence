"""Investigation agent orchestrator — bounded tool loop + structured output."""

from __future__ import annotations

import json
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from app.agent.bedrock_llm import BedrockInvestigationLLM
from app.agent.guardrails import redact_tool_payload, sanitize_user_question, validate_tool_call
from app.agent.tool_schemas import ALLOWED_TOOLS
from app.agent.tools import InvestigationTools
from app.core.config import settings
from app.core.logging import get_logger
from app.schemas.incidents import EvidenceStrength
from app.schemas.investigation_agent import (
    AgentHypothesis,
    AgentPlanStep,
    ErrorWarningSummary,
    EventCitation,
    FactKind,
    InvestigationAgentRequest,
    InvestigationAgentResponse,
    ProvenFact,
    ToolCallRecord,
)
from app.schemas.logs import TimeRangePreset

logger = get_logger(__name__)

_PRESET_MAP = {
    "15m": TimeRangePreset.LAST_15_MINUTES,
    "1h": TimeRangePreset.LAST_1_HOUR,
    "6h": TimeRangePreset.LAST_6_HOURS,
    "24h": TimeRangePreset.LAST_24_HOURS,
    "custom": TimeRangePreset.CUSTOM,
}


class InvestigationAgentOrchestrator:
    """Runs read-only investigation loops with strict budgets."""

    def __init__(
        self,
        tools: InvestigationTools | None = None,
        llm: BedrockInvestigationLLM | None = None,
    ) -> None:
        self._tools = tools or InvestigationTools()
        self._llm = llm or BedrockInvestigationLLM()

    async def investigate(self, request: InvestigationAgentRequest) -> InvestigationAgentResponse:
        investigation_id = str(uuid.uuid4())[:12]
        generated_at = datetime.now(UTC)
        question, guard_notes = sanitize_user_question(request.question)

        max_rounds = request.max_tool_rounds or settings.agent_max_iterations
        max_tool_calls = settings.agent_max_tool_calls_per_run

        messages: list[dict[str, Any]] = [{"role": "user", "content": question}]
        tool_records: list[ToolCallRecord] = []
        tool_results: list[dict[str, Any]] = []
        plan_steps: list[AgentPlanStep] = []
        tokens_estimated = len(question) // 4
        tool_call_count = 0

        tools_spec = _tools_openapi_spec()

        for iteration in range(max_rounds):
            # Only force synthesis after at least one tool round (or budget exhausted).
            force_final = iteration == max_rounds - 1 and (
                tool_call_count > 0 or iteration > 0
            )
            step = await self._llm.next_step(
                question=question,
                messages=messages,
                tools_spec=tools_spec,
                force_final=force_final,
            )
            tokens_estimated += 800

            if step.final_report is not None:
                return self._build_response(
                    investigation_id=investigation_id,
                    generated_at=generated_at,
                    question=question,
                    guard_notes=guard_notes,
                    plan_steps=plan_steps,
                    tool_records=tool_records,
                    final_report=step.final_report,
                    iteration_count=iteration + 1,
                    tokens_estimated=tokens_estimated,
                    log_groups=request.log_group_names,
                    tool_results=tool_results,
                )

            if not step.tool_calls:
                messages.append(
                    {
                        "role": "assistant",
                        "content": json.dumps({"error": "No tool_calls or final_report"}),
                    }
                )
                continue

            for tc in step.tool_calls:
                if tool_call_count >= max_tool_calls:
                    guard_notes.append(
                        f"Tool call budget exhausted ({max_tool_calls}); forcing synthesis."
                    )
                    break

                args = _inject_scope(tc.arguments, request)
                plan_steps.append(
                    AgentPlanStep(
                        step_index=len(plan_steps) + 1,
                        goal=step.thought or f"Call {tc.tool_name}",
                        tool_name=tc.tool_name,
                        rationale="Planned by investigation agent (read-only).",
                    )
                )

                start_ms = time.monotonic()
                try:
                    validated_args, vnotes = validate_tool_call(tc.tool_name, args)
                    guard_notes.extend(vnotes)
                    result = await self._tools.dispatch(tc.tool_name, validated_args)
                    result = redact_tool_payload(result)
                    success = True
                    err = None
                    summary = _summarize_tool_result(tc.tool_name, result)
                except Exception as exc:
                    success = False
                    err = str(exc)
                    result = {"error": err}
                    summary = f"Tool failed: {err}"
                    logger.warning("Tool %s failed: %s", tc.tool_name, exc)

                duration_ms = int((time.monotonic() - start_ms) * 1000)
                tool_call_count += 1
                tool_records.append(
                    ToolCallRecord(
                        call_index=len(tool_records) + 1,
                        tool_name=tc.tool_name,
                        arguments=args,
                        success=success,
                        error_message=err,
                        result_summary=summary[:2000],
                        duration_ms=duration_ms,
                    )
                )
                if success and isinstance(result, dict):
                    tool_results.append({"tool": tc.tool_name, "result": result})
                messages.append(
                    {
                        "role": "tool",
                        "name": tc.tool_name,
                        "content": json.dumps(result)[: settings.agent_max_tool_result_chars],
                    }
                )

            if tool_call_count >= max_tool_calls:
                break

        # Final synthesis pass
        final_step = await self._llm.next_step(
            question=question,
            messages=messages,
            tools_spec=tools_spec,
            force_final=True,
        )
        tokens_estimated += 600
        report = final_step.final_report or _empty_final_report(question)
        return self._build_response(
            investigation_id=investigation_id,
            generated_at=generated_at,
            question=question,
            guard_notes=guard_notes,
            plan_steps=plan_steps,
            tool_records=tool_records,
            final_report=report,
            iteration_count=max_rounds,
            tokens_estimated=tokens_estimated,
            log_groups=request.log_group_names,
            tool_results=tool_results,
        )

    def _build_response(
        self,
        *,
        investigation_id: str,
        generated_at: datetime,
        question: str,
        guard_notes: list[str],
        plan_steps: list[AgentPlanStep],
        tool_records: list[ToolCallRecord],
        final_report: dict[str, Any],
        iteration_count: int,
        tokens_estimated: int,
        log_groups: list[str],
        tool_results: list[dict[str, Any]] | None = None,
    ) -> InvestigationAgentResponse:
        proven = [_parse_fact(f) for f in final_report.get("proven_facts", [])]
        proven.extend(_facts_from_tool_records(tool_records))

        hypotheses = [_parse_hypothesis(h) for h in final_report.get("hypotheses", [])]
        errors = [_parse_error_summary(e) for e in final_report.get("error_warning_summaries", [])]
        errors.extend(_errors_from_tool_results(tool_results or []))

        # Deduplicate facts by statement prefix
        seen: set[str] = set()
        unique_facts: list[ProvenFact] = []
        for f in proven:
            key = f.statement[:120]
            if key not in seen:
                seen.add(key)
                unique_facts.append(f)

        analysis_notes = [
            "Agent operates in investigation-only mode; no remediation actions were executed.",
            f"Scope log groups: {', '.join(log_groups[:5])}"
            + ("…" if len(log_groups) > 5 else ""),
        ]
        if tokens_estimated > settings.agent_token_budget_warn:
            analysis_notes.append(
                f"Estimated token usage ({tokens_estimated}) exceeded warn threshold "
                f"({settings.agent_token_budget_warn})."
            )

        return InvestigationAgentResponse(
            investigation_id=investigation_id,
            generated_at=generated_at,
            question_sanitized=question,
            plan=plan_steps,
            tool_calls=tool_records,
            proven_facts=unique_facts[:30],
            error_warning_summaries=errors[:30],
            hypotheses=hypotheses[:10],
            executive_summary=str(final_report.get("executive_summary", ""))[:8000],
            recommended_next_steps=list(final_report.get("recommended_next_steps", []))[:20],
            remediation_recommendations=list(
                final_report.get("remediation_recommendations", [])
            )[:20],
            iteration_count=iteration_count,
            tokens_estimated=min(tokens_estimated, settings.agent_token_budget_hard),
            model_id=self._llm.model_id,
            runtime=self._llm.runtime_label,  # type: ignore[arg-type]
            guardrail_notes=guard_notes,
            analysis_notes=analysis_notes,
        )


def _inject_scope(arguments: dict[str, Any], request: InvestigationAgentRequest) -> dict[str, Any]:
    args = dict(arguments)
    preset = _PRESET_MAP.get(request.time_range_preset, TimeRangePreset.LAST_1_HOUR)

    def _replace_groups(val: Any) -> Any:
        if val == "__SCOPE__":
            return request.log_group_names
        return val

    for key, val in list(args.items()):
        if key == "log_group_names" and (val == "__SCOPE__" or val == ["__SCOPE__"]):
            args[key] = request.log_group_names
        if isinstance(val, list) and "__SCOPE__" in val:
            args[key] = request.log_group_names
        if key == "time_range_preset" and request.time_range_preset == "custom":
            args["time_range_preset"] = TimeRangePreset.CUSTOM.value
            args["start_time"] = request.start_time
            args["end_time"] = request.end_time
        elif key == "time_range_preset" and isinstance(val, str):
            args[key] = preset.value

    if request.time_range_preset == "custom":
        args.setdefault("start_time", request.start_time)
        args.setdefault("end_time", request.end_time)

    return args


def _tools_openapi_spec() -> list[dict[str, Any]]:
    return [{"name": name, "read_only": True} for name in sorted(ALLOWED_TOOLS)]


def _summarize_tool_result(tool_name: str, result: dict[str, Any]) -> str:
    if tool_name == "search_cloudwatch_logs":
        return f"Returned {result.get('event_count', 0)} log events (truncated={result.get('truncated')})."
    if tool_name == "get_grouped_error_patterns":
        return f"Found {result.get('pattern_count', 0)} error/warn pattern clusters."
    if tool_name == "get_anomaly_summaries":
        spikes = len(result.get("error_rate_spikes", []))
        return f"Anomaly status={result.get('status')}; {spikes} error-rate anomaly bucket(s)."
    if tool_name == "get_cloudwatch_metrics":
        return f"Metric {result.get('namespace')}/{result.get('metric_name')}: {result.get('datapoint_count', 0)} points."
    if tool_name == "get_deployment_metadata":
        return f"Found {result.get('deployment_count', 0)} deployment-related log entries."
    return "Tool completed."


def _parse_fact(raw: dict[str, Any]) -> ProvenFact:
    citations = [EventCitation.model_validate(c) for c in raw.get("citations", [])]
    kind = raw.get("kind", "proven")
    try:
        fk = FactKind(kind)
    except ValueError:
        fk = FactKind.PROVEN
    return ProvenFact(
        fact_id=str(raw.get("fact_id", uuid.uuid4())[:8]),
        kind=fk,
        statement=str(raw.get("statement", ""))[:2000],
        citations=citations,
        source_tool=str(raw.get("source_tool", "unknown")),
    )


def _parse_hypothesis(raw: dict[str, Any]) -> AgentHypothesis:
    strength_raw = str(raw.get("evidence_strength", "speculative")).lower()
    try:
        strength = EvidenceStrength(strength_raw)
    except ValueError:
        strength = EvidenceStrength.SPECULATIVE
    return AgentHypothesis(
        hypothesis_id=str(raw.get("hypothesis_id", uuid.uuid4())[:8]),
        rank=int(raw.get("rank", 1)),
        title=str(raw.get("title", ""))[:300],
        description=str(raw.get("description", ""))[:4000],
        evidence_strength=strength,
        supporting_fact_ids=list(raw.get("supporting_fact_ids", [])),
        contradicting_notes=list(raw.get("contradicting_notes", [])),
        causation_caveat=raw.get("causation_caveat"),
        investigation_steps=list(raw.get("investigation_steps", []))[:15],
        remediation_suggestions=list(raw.get("remediation_suggestions", []))[:15],
    )


def _parse_error_summary(raw: dict[str, Any]) -> ErrorWarningSummary:
    citations = [EventCitation.model_validate(c) for c in raw.get("citations", [])]
    return ErrorWarningSummary(
        severity=str(raw.get("severity", "ERROR")),
        pattern_or_message=str(raw.get("pattern_or_message", ""))[:500],
        occurrence_hint=raw.get("occurrence_hint"),
        log_groups=list(raw.get("log_groups", [])),
        citations=citations,
    )


def _facts_from_tool_records(records: list[ToolCallRecord]) -> list[ProvenFact]:
    facts: list[ProvenFact] = []
    for rec in records:
        if not rec.success:
            continue
        facts.append(
            ProvenFact(
                fact_id=f"tool-{rec.call_index}",
                kind=FactKind.PROVEN,
                statement=rec.result_summary,
                citations=[],
                source_tool=rec.tool_name,
            )
        )
    return facts


def _errors_from_tool_results(tool_results: list[dict[str, Any]]) -> list[ErrorWarningSummary]:
    summaries: list[ErrorWarningSummary] = []
    for entry in tool_results:
        if entry.get("tool") != "search_cloudwatch_logs":
            continue
        payload = entry.get("result", {})
        if not isinstance(payload, dict):
            continue
        for ev in payload.get("events", [])[:10]:
            msg = str(ev.get("message", ""))[:500]
            summaries.append(
                ErrorWarningSummary(
                    severity="ERROR",
                    pattern_or_message=msg,
                    log_groups=[str(ev.get("log_group", ""))],
                    citations=[
                        EventCitation(
                            log_group=str(ev.get("log_group", "")),
                            timestamp=datetime.fromisoformat(
                                str(ev.get("timestamp", datetime.now(UTC).isoformat())).replace(
                                    "Z", "+00:00"
                                )
                            ),
                            ptr=ev.get("ptr"),
                            log_stream=ev.get("log_stream"),
                            excerpt=msg[:200],
                        )
                    ],
                )
            )
    return summaries


def _empty_final_report(question: str) -> dict[str, Any]:
    return {
        "executive_summary": f"Investigation for '{question[:200]}' completed with limited model output.",
        "proven_facts": [],
        "hypotheses": [],
        "recommended_next_steps": ["Retry with a narrower time window or fewer log groups."],
        "remediation_recommendations": [],
    }
