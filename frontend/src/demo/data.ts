import type {
  AnomalyEvent,
  IncidentFinding,
  LogEntry,
  OverviewSnapshot,
  TimeSeriesPoint,
  TrendsSnapshot,
} from "@/types/ops";

function hoursAgo(h: number): string {
  return new Date(Date.now() - h * 3600_000).toISOString();
}

function minutesAgo(m: number): string {
  return new Date(Date.now() - m * 60_000).toISOString();
}

function series(base: number, points: number, spikeAt?: number): TimeSeriesPoint[] {
  const out: TimeSeriesPoint[] = [];
  for (let i = points - 1; i >= 0; i--) {
    const t = new Date(Date.now() - i * 5 * 60_000).toISOString();
    let v = base + Math.sin(i / 3) * (base * 0.15);
    if (spikeAt !== undefined && i === spikeAt) v = base * 4.2;
    out.push({ timestamp: t, value: Math.max(0, Math.round(v)) });
  }
  return out;
}

export const DEMO_LOG_GROUPS = [
  "/aws/ecs/prod-api",
  "/aws/ecs/prod-worker",
  "/aws/lambda/payment-processor",
  "/aws/lambda/order-processor",
  "/aws/rds/cluster-main/error",
  "/aws/eks/prod-cluster/frontend",
];

export const DEMO_ACCOUNTS = ["production", "staging"];
export const DEMO_REGIONS = ["us-east-1", "us-west-2"];

export const demoAnomalies: AnomalyEvent[] = [
  {
    id: "an-1",
    title: "RDS CPU saturation",
    severity: "critical",
    service: "db-cluster-main",
    detectedAt: minutesAgo(18),
    metric: "CPUUtilization",
    changeRatio: 6.2,
  },
  {
    id: "an-2",
    title: "ALB target 5xx spike",
    severity: "high",
    service: "prod-alb",
    detectedAt: minutesAgo(12),
    metric: "HTTPCode_Target_5XX_Count",
    changeRatio: 8.1,
  },
  {
    id: "an-3",
    title: "ECS task stop rate",
    severity: "high",
    service: "prod-api",
    detectedAt: minutesAgo(14),
    metric: "StoppedTaskCount",
    changeRatio: 4.5,
  },
  {
    id: "an-4",
    title: "Lambda error rate",
    severity: "medium",
    service: "payment-processor",
    detectedAt: minutesAgo(25),
    metric: "Errors",
    changeRatio: 2.1,
  },
  {
    id: "an-5",
    title: "EKS pod restart burst",
    severity: "medium",
    service: "frontend",
    detectedAt: hoursAgo(1),
    metric: "PodRestartCount",
    changeRatio: 3.0,
  },
];

export const demoOverview: OverviewSnapshot = {
  generatedAt: new Date().toISOString(),
  kpis: [
    { id: "errors", label: "Errors (1h)", value: 847, deltaPct: 312, trend: "up", severity: "critical" },
    { id: "warnings", label: "Warnings (1h)", value: 214, deltaPct: 48, trend: "up", severity: "high" },
    { id: "anomalies", label: "Active anomalies", value: 5, trend: "up", severity: "high" },
    { id: "services", label: "Affected services", value: 6, trend: "up", severity: "medium" },
    { id: "mttr", label: "Est. MTTR", value: "42m", trend: "flat", severity: "info" },
    { id: "alarms", label: "CloudWatch alarms", value: 3, trend: "up", severity: "critical" },
  ],
  errorSeries: series(12, 24, 3),
  warnSeries: series(8, 24, 5),
  anomalySeries: series(0, 24, 4),
  affectedServices: [
    { name: "db-cluster-main", source: "RDS", errorCount: 18, status: "degraded", lastSeen: minutesAgo(2) },
    { name: "prod-api", source: "ECS", errorCount: 124, status: "degraded", lastSeen: minutesAgo(1) },
    { name: "prod-alb", source: "ALB", errorCount: 89, status: "degraded", lastSeen: minutesAgo(3) },
    { name: "payment-processor", source: "Lambda", errorCount: 34, status: "degraded", lastSeen: minutesAgo(8) },
    { name: "data-processor", source: "EKS", errorCount: 21, status: "degraded", lastSeen: minutesAgo(4) },
    { name: "order-processor", source: "Lambda", errorCount: 12, status: "unknown", lastSeen: minutesAgo(15) },
  ],
  recentAnomalies: demoAnomalies.slice(0, 4),
};

const logMessages = [
  ["critical", "FATAL: remaining connection slots are reserved for superuser connections"],
  ["high", "SQLAlchemyError: could not connect to server: Connection refused"],
  ["high", "503 Service Unavailable — target group tg-prod-api unhealthy"],
  ["high", "Task timed out after 30.0 seconds — Memory Used: 508MB / 512MB"],
  ["medium", "Retrying GetItem after ProvisionedThroughputExceeded (attempt 2/3)"],
  ["medium", "Circuit breaker OPEN for service=user-profile failures=15 threshold=10"],
  ["info", "Deployment started: version=v2.3.5 environment=production replicas=3"],
  ["high", "OOMKilled: Container api exceeded memory limit 512Mi"],
];

export const demoLogs: LogEntry[] = Array.from({ length: 120 }, (_, i) => {
  const [sev, msg] = logMessages[i % logMessages.length] as [LogEntry["severity"], string];
  const lg = DEMO_LOG_GROUPS[i % DEMO_LOG_GROUPS.length];
  const service = lg.split("/").pop() ?? "unknown";
  return {
    id: `log-${i}`,
    timestamp: minutesAgo(i * 2),
    severity: sev,
    logGroup: lg,
    logStream: `stream/${i % 5}`,
    message: msg,
    ptr: `demo-ptr-${i.toString(16).padStart(8, "0")}`,
    service,
  };
});

export const demoIncidents: IncidentFinding[] = [
  {
    id: "inc-db-cascade",
    title: "Database connection exhaustion cascading to API tier",
    priority: 1,
    severity: "critical",
    status: "investigating",
    affectedServices: ["db-cluster-main", "prod-api", "prod-alb", "payment-processor"],
    startedAt: minutesAgo(22),
    updatedAt: minutesAgo(2),
    summary:
      "RDS max_connections reached; ECS and Lambda callers report connection refused; ALB 5xx elevated.",
    hypothesis: "RDS saturation in db-cluster-main (dependency propagation to callers)",
    evidenceStrength: "moderate",
    timeline: [
      {
        id: "t1",
        timestamp: minutesAgo(20),
        source: "RDS",
        description: "CPUUtilization peaked at 96%",
        severity: "high",
      },
      {
        id: "t2",
        timestamp: minutesAgo(18),
        source: "RDS",
        description: "Max connections reached — FATAL in error log",
        severity: "critical",
      },
      {
        id: "t3",
        timestamp: minutesAgo(17),
        source: "ECS",
        description: "prod-api task failures (connection refused)",
        severity: "high",
      },
      {
        id: "t4",
        timestamp: minutesAgo(15),
        source: "ALB",
        description: "Target 503 errors increasing",
        severity: "high",
      },
      {
        id: "t5",
        timestamp: minutesAgo(14),
        source: "CloudWatch",
        description: "Alarm: prod-api-HighErrorRate → ALARM",
        severity: "critical",
        isDeployment: false,
      },
    ],
  },
  {
    id: "inc-deploy",
    title: "Post-deployment error regression — order-processor v2.3.5",
    priority: 2,
    severity: "high",
    status: "open",
    affectedServices: ["order-processor", "prod-alb"],
    startedAt: hoursAgo(2),
    updatedAt: minutesAgo(45),
    summary: "Error rate increased after rolling deploy; Lambda timeouts and OOM kills observed.",
    hypothesis: "Deployment regression in order-processor (v2.3.5)",
    evidenceStrength: "strong",
    timeline: [
      {
        id: "d1",
        timestamp: hoursAgo(2),
        source: "ECS",
        description: "Deployment complete: version=v2.3.5",
        severity: "info",
        isDeployment: true,
      },
      {
        id: "d2",
        timestamp: minutesAgo(114),
        source: "Lambda",
        description: "Timeout rate elevated on order-processor",
        severity: "high",
      },
    ],
  },
];

export const demoTrends: TrendsSnapshot = {
  errorFrequency: series(15, 48, 40),
  anomalyHistory: demoAnomalies,
  serviceHealth: [
    { service: "prod-api", uptimePct: 97.2, errorRate: 4.8 },
    { service: "db-cluster-main", uptimePct: 99.1, errorRate: 0.9 },
    { service: "prod-alb", uptimePct: 98.4, errorRate: 2.1 },
    { service: "payment-processor", uptimePct: 99.5, errorRate: 0.4 },
    { service: "frontend", uptimePct: 96.8, errorRate: 1.2 },
  ],
  notes: [
    "Demo dataset — connect backend for live CloudWatch metrics and correlation.",
    "Error frequency uses 5-minute buckets over the last 4 hours.",
  ],
};
