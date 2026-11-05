import { useOverview } from "@/api/opsQueries";
import { KpiCard } from "@/components/common/KpiCard";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/common/Card";
import { ErrorState } from "@/components/common/ErrorState";
import { LoadingState } from "@/components/common/LoadingState";
import { TimeSeriesChart } from "@/components/charts/TimeSeriesChart";
import { SeverityBadge } from "@/components/ops/SeverityBadge";
import { Header } from "@/components/layout/Header";
import { ThemeToggle } from "@/components/layout/ThemeToggle";
import { Badge } from "@/components/common/Badge";
import { isDemoMode } from "@/demo/preferences";

export function Overview() {
  const { data, isLoading, error, refetch } = useOverview();

  return (
    <div>
      <Header
        title="Operations overview"
        description="Errors, warnings, anomalies, and affected services across your estate."
      >
        <div className="flex items-center gap-2">
          {isDemoMode() && <Badge variant="outline">Demo data</Badge>}
          <ThemeToggle />
        </div>
      </Header>
      <div className="space-y-6 p-6 lg:p-8">
        {isLoading && <LoadingState label="Loading operational metrics…" />}
        {error && !isLoading && (
          <ErrorState message={error instanceof Error ? error.message : "Failed to load overview"} onRetry={() => refetch()} />
        )}
        {data && !isLoading && (
          <>
            <div className="grid grid-cols-2 gap-3 xl:grid-cols-3 2xl:grid-cols-6">
              {data.kpis.map((k) => (
                <KpiCard key={k.id} metric={k} />
              ))}
            </div>
            <div className="grid gap-4 lg:grid-cols-3">
              <Card className="lg:col-span-2">
                <CardHeader>
                  <CardTitle>Signal volume</CardTitle>
                  <CardDescription>5-minute buckets — errors, warnings, anomaly flags</CardDescription>
                </CardHeader>
                <CardContent>
                  <TimeSeriesChart
                    ariaLabel="Errors warnings and anomalies over time"
                    series={[
                      { key: "err", label: "Errors", data: data.errorSeries, color: "var(--color-destructive)" },
                      { key: "warn", label: "Warnings", data: data.warnSeries, color: "var(--color-warning)" },
                      { key: "anom", label: "Anomalies", data: data.anomalySeries, color: "var(--color-primary)" },
                    ]}
                  />
                </CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle>Recent anomalies</CardTitle>
                  <CardDescription>Statistically elevated signals</CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  {data.recentAnomalies.map((a) => (
                    <div key={a.id} className="rounded-md border border-border p-3">
                      <div className="flex items-start justify-between gap-2">
                        <p className="text-sm font-medium">{a.title}</p>
                        <SeverityBadge severity={a.severity} compact />
                      </div>
                      <p className="mt-1 text-xs text-muted-foreground">
                        {a.service} · {a.metric}
                        {a.changeRatio != null && ` · ${a.changeRatio.toFixed(1)}× baseline`}
                      </p>
                    </div>
                  ))}
                </CardContent>
              </Card>
            </div>
            <Card>
              <CardHeader>
                <CardTitle>Affected services</CardTitle>
                <CardDescription>Services with elevated error signals in the current window</CardDescription>
              </CardHeader>
              <CardContent className="overflow-x-auto">
                <table className="w-full min-w-[640px] text-left text-sm">
                  <thead className="border-b border-border text-xs uppercase text-muted-foreground">
                    <tr>
                      <th className="pb-2 pr-4 font-medium">Service</th>
                      <th className="pb-2 pr-4 font-medium">Source</th>
                      <th className="pb-2 pr-4 font-medium">Errors</th>
                      <th className="pb-2 pr-4 font-medium">Status</th>
                      <th className="pb-2 font-medium">Last seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.affectedServices.map((s) => (
                      <tr key={s.name} className="border-b border-border/60 last:border-0">
                        <td className="py-3 pr-4 font-medium">{s.name}</td>
                        <td className="py-3 pr-4 text-muted-foreground">{s.source}</td>
                        <td className="py-3 pr-4 tabular-nums">{s.errorCount}</td>
                        <td className="py-3 pr-4">
                          <Badge variant={s.status === "degraded" ? "destructive" : "outline"}>
                            {s.status}
                          </Badge>
                        </td>
                        <td className="py-3 text-xs text-muted-foreground">
                          {new Date(s.lastSeen).toLocaleString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </CardContent>
            </Card>
          </>
        )}
      </div>
    </div>
  );
}
