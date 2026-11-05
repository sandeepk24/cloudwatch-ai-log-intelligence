export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface TimeSeriesPoint {
  timestamp: string;
  value: number;
  label?: string;
}

export interface KpiMetric {
  id: string;
  label: string;
  value: number | string;
  deltaPct?: number;
  trend?: "up" | "down" | "flat";
  severity?: Severity;
  unit?: string;
}

export interface AffectedService {
  name: string;
  source: string;
  errorCount: number;
  status: "degraded" | "healthy" | "unknown";
  lastSeen: string;
}

export interface OverviewSnapshot {
  generatedAt: string;
  kpis: KpiMetric[];
  errorSeries: TimeSeriesPoint[];
  warnSeries: TimeSeriesPoint[];
  anomalySeries: TimeSeriesPoint[];
  affectedServices: AffectedService[];
  recentAnomalies: AnomalyEvent[];
}

export interface AnomalyEvent {
  id: string;
  title: string;
  severity: Severity;
  service: string;
  detectedAt: string;
  metric: string;
  changeRatio?: number;
}

export interface LogEntry {
  id: string;
  timestamp: string;
  severity: Severity;
  logGroup: string;
  logStream?: string;
  message: string;
  ptr?: string;
  service: string;
}

export interface LogSearchFilters {
  query: string;
  severity: Severity | "all";
  logGroup: string;
  service: string;
  page: number;
  pageSize: number;
}

export interface LogSearchResult {
  total: number;
  page: number;
  pageSize: number;
  entries: LogEntry[];
}

export interface IncidentFinding {
  id: string;
  title: string;
  priority: number;
  severity: Severity;
  status: "open" | "investigating" | "mitigated";
  affectedServices: string[];
  startedAt: string;
  updatedAt: string;
  summary: string;
  hypothesis: string;
  evidenceStrength: "strong" | "moderate" | "weak" | "speculative";
  timeline: TimelineEvent[];
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  source: string;
  description: string;
  severity: Severity;
  isDeployment?: boolean;
}

export interface InvestigationRequest {
  question: string;
  logGroupNames: string[];
  timeRangePreset: "15m" | "1h" | "6h" | "24h";
}

export interface InvestigationResult {
  investigationId: string;
  executiveSummary: string;
  provenFacts: { id: string; statement: string; sourceTool: string }[];
  hypotheses: {
    rank: number;
    title: string;
    description: string;
    evidenceStrength: string;
    causationCaveat?: string;
  }[];
  toolCalls: { toolName: string; success: boolean; summary: string }[];
  recommendedSteps: string[];
}

export interface TrendsSnapshot {
  errorFrequency: TimeSeriesPoint[];
  anomalyHistory: AnomalyEvent[];
  serviceHealth: { service: string; uptimePct: number; errorRate: number }[];
  notes: string[];
}

export interface WorkspacePreferences {
  demoData: boolean;
  accounts: string[];
  regions: string[];
  logGroups: string[];
  queryBudgetBytes: number;
  maxLogGroupsPerQuery: number;
}
