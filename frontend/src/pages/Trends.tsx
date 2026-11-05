import { useTrends } from "@/api/opsQueries";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/common/Card";
import { ErrorState } from "@/components/common/ErrorState";
import { LoadingState } from "@/components/common/LoadingState";
import { TimeSeriesChart } from "@/components/charts/TimeSeriesChart";
import { SeverityBadge } from "@/components/ops/SeverityBadge";
import { Header } from "@/components/layout/Header";
import { ThemeToggle } from "@/components/layout/ThemeToggle";

export function Trends() {
  const { data, isLoading, error, refetch } = useTrends();

  return (
    <div>
      <Header title="Trends" description="Error frequency, anomaly history, and service health indicators.">
        <ThemeToggle />
      </Header>
      <div className="space-y-6 p-6 lg:p-8">
        {isLoading && <LoadingState label="Loading trend data…" />}
        {error && !isLoading && (
          <ErrorState message={error instanceof Error ? error.message : "Failed to load trends"} onRetry={() => refetch()} />
        )}
        {data && (
          <>
            <Card>
              <CardHeader>
                <CardTitle>Error frequency</CardTitle>
                <CardDescription>5-minute buckets — last 4 hours</CardDescription>
              </CardHeader>
              <CardContent>
                <TimeSeriesChart
                  series={[
                    {
                      key: "errors",
                      label: "Errors / bucket",
                      data: data.errorFrequency,
                      color: "var(--color-destructive)",
                    },
                  ]}
                />
              </CardContent>
            </Card>
            <div className="grid gap-4 lg:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle>Anomaly history</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {data.anomalyHistory.map((a) => (
                    <div key={a.id} className="flex items-start justify-between gap-3 border-b border-border pb-3 last:border-0">
                      <div>
                        <p className="text-sm font-medium">{a.title}</p>
                        <p className="text-xs text-muted-foreground">
                          {new Date(a.detectedAt).toLocaleString()} · {a.service}
                        </p>
                      </div>
                      <SeverityBadge severity={a.severity} compact />
                    </div>
                  ))}
                </CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle>Service health</CardTitle>
                  <CardDescription>Uptime and error rate (demo estimates)</CardDescription>
                </CardHeader>
                <CardContent className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead className="text-xs uppercase text-muted-foreground">
                      <tr>
                        <th className="pb-2 text-left font-medium">Service</th>
                        <th className="pb-2 text-right font-medium">Uptime</th>
                        <th className="pb-2 text-right font-medium">Err/min</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.serviceHealth.map((s) => (
                        <tr key={s.service} className="border-t border-border/60">
                          <td className="py-2">{s.service}</td>
                          <td className="py-2 text-right tabular-nums">{s.uptimePct.toFixed(1)}%</td>
                          <td className="py-2 text-right tabular-nums">{s.errorRate.toFixed(2)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </CardContent>
              </Card>
            </div>
            <ul className="text-xs text-muted-foreground">
              {data.notes.map((n) => (
                <li key={n}>• {n}</li>
              ))}
            </ul>
          </>
        )}
      </div>
    </div>
  );
}
