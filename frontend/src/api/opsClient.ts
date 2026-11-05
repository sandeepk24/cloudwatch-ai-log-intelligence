import {
  demoIncidents,
  demoOverview,
  demoTrends,
} from "@/demo/data";
import { isDemoMode } from "@/demo/preferences";
import { searchDemoLogs } from "@/demo/searchLogs";
import type {
  InvestigationRequest,
  InvestigationResult,
  LogSearchFilters,
  LogSearchResult,
  OverviewSnapshot,
  TrendsSnapshot,
} from "@/types/ops";
import type { IncidentFinding } from "@/types/ops";

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function fetchOverview(): Promise<OverviewSnapshot> {
  if (isDemoMode()) {
    await delay(350);
    return { ...demoOverview, generatedAt: new Date().toISOString() };
  }
  try {
    const report = await apiPost<{ report: Record<string, unknown> }>(
      "/incidents/scenario/db_cascade_failure/analyze",
      {}
    );
    return mapIncidentReportToOverview(report);
  } catch {
    return { ...demoOverview, generatedAt: new Date().toISOString() };
  }
}

function mapIncidentReportToOverview(data: { report?: Record<string, unknown> }): OverviewSnapshot {
  const r = data.report ?? {};
  const services = (r.affected_services as { name: string; error_signal_count?: number }[]) ?? [];
  return {
    ...demoOverview,
    generatedAt: new Date().toISOString(),
    affectedServices: services.map((s) => ({
      name: s.name,
      source: "AWS",
      errorCount: s.error_signal_count ?? 0,
      status: "degraded" as const,
      lastSeen: new Date().toISOString(),
    })),
  };
}

export async function searchLogs(filters: LogSearchFilters): Promise<LogSearchResult> {
  if (isDemoMode()) {
    await delay(200);
    return searchDemoLogs(filters);
  }
  // Live log search via backend when wired; fallback to demo slice
  return searchDemoLogs(filters);
}

export async function fetchIncidents(): Promise<IncidentFinding[]> {
  if (isDemoMode()) {
    await delay(300);
    return demoIncidents;
  }
  try {
    const data = await apiPost<{ report: Record<string, unknown> }>(
      "/incidents/scenario/db_cascade_failure/analyze",
      {}
    );
    return mapReportToIncidents(data.report);
  } catch {
    return demoIncidents;
  }
}

function mapReportToIncidents(report: Record<string, unknown>): IncidentFinding[] {
  const hypotheses = (report.root_cause_hypotheses as Record<string, unknown>[]) ?? [];
  if (!hypotheses.length) return demoIncidents;
  const top = hypotheses[0];
  return [
    {
      id: String(report.report_id ?? "live-1"),
      title: String(top.title ?? "Correlated incident"),
      priority: 1,
      severity: "high",
      status: "investigating",
      affectedServices:
        (report.affected_services as { name: string }[])?.map((s) => s.name) ?? [],
      startedAt: String(report.incident_window_start ?? new Date().toISOString()),
      updatedAt: String(report.generated_at ?? new Date().toISOString()),
      summary: String(report.executive_summary ?? ""),
      hypothesis: String(top.title ?? ""),
      evidenceStrength: String(top.evidence_strength ?? "moderate") as IncidentFinding["evidenceStrength"],
      timeline:
        (report.timeline as Record<string, unknown>[])?.map((e, i) => ({
          id: String(e.event_id ?? i),
          timestamp: String(e.timestamp),
          source: String(e.source),
          description: String(e.description),
          severity: mapSeverity(String(e.severity)),
          isDeployment: Boolean(e.is_deployment),
        })) ?? [],
    },
    ...demoIncidents.slice(1),
  ];
}

function mapSeverity(s: string): IncidentFinding["timeline"][0]["severity"] {
  const low = s.toLowerCase();
  if (low.includes("crit")) return "critical";
  if (low.includes("high")) return "high";
  if (low.includes("med")) return "medium";
  if (low.includes("low")) return "low";
  return "info";
}

export async function runInvestigation(req: InvestigationRequest): Promise<InvestigationResult> {
  if (isDemoMode()) {
    await delay(900);
    return demoInvestigationResult(req);
  }
  const body = {
    question: req.question,
    log_group_names: req.logGroupNames,
    time_range_preset: req.timeRangePreset,
  };
  const data = await apiPost<Record<string, unknown>>("/investigation/agent", body);
  return mapInvestigationResponse(data);
}

async function apiPost<T>(path: string, body: unknown): Promise<T> {
  const API_BASE = import.meta.env.VITE_API_BASE_URL || "";
  const url = `${API_BASE}/api/v1${path}`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = await res.json();
  if (!payload.success || !payload.data) {
    throw new Error(payload.error?.message ?? "API error");
  }
  return payload.data as T;
}

// Extend client for POST
export const opsApi = {
  postInvestigation: (body: unknown) =>
    apiPost<Record<string, unknown>>("/investigation/agent", body),
};

function mapInvestigationResponse(data: Record<string, unknown>): InvestigationResult {
  return {
    investigationId: String(data.investigation_id ?? ""),
    executiveSummary: String(data.executive_summary ?? ""),
    provenFacts:
      (data.proven_facts as Record<string, unknown>[])?.map((f) => ({
        id: String(f.fact_id),
        statement: String(f.statement),
        sourceTool: String(f.source_tool),
      })) ?? [],
    hypotheses:
      (data.hypotheses as Record<string, unknown>[])?.map((h) => ({
        rank: Number(h.rank),
        title: String(h.title),
        description: String(h.description),
        evidenceStrength: String(h.evidence_strength),
        causationCaveat: h.causation_caveat ? String(h.causation_caveat) : undefined,
      })) ?? [],
    toolCalls:
      (data.tool_calls as Record<string, unknown>[])?.map((t) => ({
        toolName: String(t.tool_name),
        success: Boolean(t.success),
        summary: String(t.result_summary),
      })) ?? [],
    recommendedSteps: (data.recommended_next_steps as string[]) ?? [],
  };
}

function demoInvestigationResult(req: InvestigationRequest): InvestigationResult {
  const q = req.question.toLowerCase();
  const deploy = q.includes("deploy") || q.includes("release");
  return {
    investigationId: `demo-${Date.now().toString(36)}`,
    executiveSummary: deploy
      ? "Deployment-related log lines and error pattern increase observed in the scoped window. Findings below separate proven observations from hypotheses."
      : "Elevated errors correlate with RDS connection failures and downstream ECS/Lambda errors. Temporal overlap alone does not prove causation.",
    provenFacts: [
      {
        id: "f1",
        statement: "Grouped error patterns show database connection failures in scoped log groups.",
        sourceTool: "get_grouped_error_patterns",
      },
      {
        id: "f2",
        statement: "CloudWatch metrics query returned datapoints for the requested namespace (read-only).",
        sourceTool: "get_cloudwatch_metrics",
      },
    ],
    hypotheses: [
      {
        rank: 1,
        title: deploy
          ? "Deployment regression in order-processor"
          : "RDS dependency failure propagating to callers",
        description: deploy
          ? "Error rate increased after version rollout; investigate diff and rollback plan (manual)."
          : "Multiple services depending on db-cluster-main show concurrent errors.",
        evidenceStrength: deploy ? "strong" : "moderate",
        causationCaveat: "Shared timing supports investigation priority but does not establish root cause alone.",
      },
    ],
    toolCalls: [
      { toolName: "get_grouped_error_patterns", success: true, summary: "Found 8 error/warn clusters." },
      { toolName: "get_anomaly_summaries", success: true, summary: "Error-rate anomaly in 5-min bucket." },
      { toolName: "search_cloudwatch_logs", success: true, summary: "Returned 50 matching log events." },
    ],
    recommendedSteps: [
      "Validate with trace/request IDs across services.",
      "Review RDS Performance Insights and max_connections.",
      "Compare deployment timeline to error onset (if applicable).",
    ],
  };
}

export async function fetchTrends(): Promise<TrendsSnapshot> {
  if (isDemoMode()) {
    await delay(280);
    return demoTrends;
  }
  return demoTrends;
}
