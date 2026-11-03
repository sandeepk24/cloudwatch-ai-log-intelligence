"""Schemas for the AI Log Investigation Agent (Bedrock / Strands).

Structured outputs are validated with Pydantic — the model must not emit
arbitrary confidence percentages; hypothesis strength uses the same
rule-based EvidenceStrength enum as the correlation engine where applicable.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.schemas.incidents import EvidenceStrength


class FactKind(StrEnum):
    PROVEN = "proven"  # Directly observed in tool output
    INFERRED = "inferred"  # Derived from multiple observations with explicit rationale
    HYPOTHESIS = "hypothesis"  # Not yet confirmed


class EventCitation(BaseModel):
    """Pointer back to original CloudWatch evidence."""

    log_group: str
    timestamp: datetime
    ptr: str | None = None
    log_stream: str | None = None
    signal_id: str | None = None
    excerpt: str = Field(max_length=500)


class ProvenFact(BaseModel):
    fact_id: str
    kind: FactKind = FactKind.PROVEN
    statement: str = Field(max_length=2000)
    citations: list[EventCitation] = Field(default_factory=list)
    source_tool: str


class AgentHypothesis(BaseModel):
    hypothesis_id: str
    rank: int = Field(ge=1, le=20)
    title: str = Field(max_length=300)
    description: str = Field(max_length=4000)
    evidence_strength: EvidenceStrength
    supporting_fact_ids: list[str] = Field(default_factory=list)
    contradicting_notes: list[str] = Field(default_factory=list)
    causation_caveat: str | None = None
    investigation_steps: list[str] = Field(default_factory=list)
    remediation_suggestions: list[str] = Field(
        default_factory=list,
        description="Recommendations only — never executed automatically.",
    )


class ErrorWarningSummary(BaseModel):
    severity: str
    pattern_or_message: str = Field(max_length=500)
    occurrence_hint: str | None = None
    log_groups: list[str] = Field(default_factory=list)
    citations: list[EventCitation] = Field(default_factory=list)


class AgentPlanStep(BaseModel):
    step_index: int
    goal: str = Field(max_length=500)
    tool_name: str
    rationale: str = Field(max_length=1000)


class ToolCallRecord(BaseModel):
    call_index: int
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    success: bool
    error_message: str | None = None
    result_summary: str = Field(max_length=2000)
    duration_ms: int = 0


class InvestigationAgentRequest(BaseModel):
    """User troubleshooting question and investigation scope."""

    question: str = Field(..., min_length=3, max_length=4000)
    log_group_names: list[str] = Field(..., min_length=1, max_length=20)
    time_range_preset: str = Field(default="1h", pattern=r"^(15m|1h|6h|24h|custom)$")
    start_time: datetime | None = None
    end_time: datetime | None = None
    account_alias: str | None = Field(default=None, max_length=128)
    service_hint: str | None = Field(default=None, max_length=128)
    include_metrics: bool = True
    include_deployments: bool = True
    max_tool_rounds: int | None = Field(default=None, ge=1, le=10)


class InvestigationAgentResponse(BaseModel):
    investigation_id: str
    generated_at: datetime
    question_sanitized: str
    plan: list[AgentPlanStep] = Field(default_factory=list)
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    proven_facts: list[ProvenFact] = Field(default_factory=list)
    error_warning_summaries: list[ErrorWarningSummary] = Field(default_factory=list)
    hypotheses: list[AgentHypothesis] = Field(default_factory=list)
    executive_summary: str = Field(max_length=8000)
    recommended_next_steps: list[str] = Field(default_factory=list)
    remediation_recommendations: list[str] = Field(
        default_factory=list,
        description="Human-in-the-loop only; agent never applies changes.",
    )
    iteration_count: int = Field(ge=0)
    tokens_estimated: int = Field(ge=0)
    model_id: str | None = None
    runtime: Literal["bedrock", "bedrock_mock", "strands"] = "bedrock"
    guardrail_notes: list[str] = Field(default_factory=list)
    analysis_notes: list[str] = Field(default_factory=list)


class BedrockToolCallPayload(BaseModel):
    """Model-emitted tool invocation (validated before execution)."""

    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class BedrockAgentStepPayload(BaseModel):
    """One agent loop step from the model."""

    thought: str | None = Field(default=None, max_length=2000)
    tool_calls: list[BedrockToolCallPayload] = Field(default_factory=list)
    final_report: dict[str, Any] | None = None
