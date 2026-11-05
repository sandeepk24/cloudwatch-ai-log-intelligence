import { useState } from "react";
import { useIncidents } from "@/api/opsQueries";
import { Badge } from "@/components/common/Badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/common/Card";
import { EmptyState } from "@/components/common/EmptyState";
import { ErrorState } from "@/components/common/ErrorState";
import { LoadingState } from "@/components/common/LoadingState";
import { IncidentTimeline } from "@/components/ops/IncidentTimeline";
import { SeverityBadge } from "@/components/ops/SeverityBadge";
import { Header } from "@/components/layout/Header";
import { ThemeToggle } from "@/components/layout/ThemeToggle";
import { cn } from "@/lib/utils";

export function IncidentCenter() {
  const { data, isLoading, error, refetch } = useIncidents();
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const selected = data?.find((i) => i.id === selectedId) ?? data?.[0];

  return (
    <div className="flex h-full min-h-0 flex-col">
      <Header
        title="Incident center"
        description="Prioritized investigation findings with timelines and evidence strength."
      >
        <ThemeToggle />
      </Header>
      <div className="grid min-h-0 flex-1 gap-0 lg:grid-cols-[360px_1fr]">
        <aside className="border-b border-border lg:border-b-0 lg:border-r">
          <div className="p-4">
            {isLoading && <LoadingState label="Loading incidents…" />}
            {error && !isLoading && (
              <ErrorState
                message={error instanceof Error ? error.message : "Failed to load incidents"}
                onRetry={() => refetch()}
              />
            )}
            {data && data.length === 0 && <EmptyState title="No open incidents" />}
            {data && data.length > 0 && (
              <ul className="space-y-2" aria-label="Incident list">
                {data.map((inc) => (
                  <li key={inc.id}>
                    <button
                      type="button"
                      onClick={() => setSelectedId(inc.id)}
                      className={cn(
                        "w-full rounded-lg border p-3 text-left transition-colors",
                        selected?.id === inc.id
                          ? "border-primary/50 bg-primary/10"
                          : "border-border hover:bg-accent/40"
                      )}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <span className="text-xs font-semibold text-primary">P{inc.priority}</span>
                        <SeverityBadge severity={inc.severity} compact />
                      </div>
                      <p className="mt-1 text-sm font-medium leading-snug">{inc.title}</p>
                      <p className="mt-2 line-clamp-2 text-xs text-muted-foreground">{inc.summary}</p>
                      <Badge variant="outline" className="mt-2">
                        {inc.status}
                      </Badge>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </aside>
        <section className="overflow-y-auto p-6">
          {!selected && !isLoading && (
            <EmptyState title="Select an incident" description="Choose a finding from the list to view details." />
          )}
          {selected && (
            <div className="mx-auto max-w-3xl space-y-6">
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={selected.severity} />
                  <Badge variant="outline">Evidence: {selected.evidenceStrength}</Badge>
                </div>
                <h2 className="mt-3 text-xl font-semibold">{selected.title}</h2>
                <p className="mt-2 text-sm text-muted-foreground">{selected.summary}</p>
              </div>
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Top hypothesis</CardTitle>
                  <CardDescription>Not confirmed root cause — validate with traces and metrics</CardDescription>
                </CardHeader>
                <CardContent className="text-sm">{selected.hypothesis}</CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Timeline</CardTitle>
                  <CardDescription>Chronological correlated events</CardDescription>
                </CardHeader>
                <CardContent>
                  <IncidentTimeline events={selected.timeline} />
                </CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Affected services</CardTitle>
                </CardHeader>
                <CardContent className="flex flex-wrap gap-2">
                  {selected.affectedServices.map((s) => (
                    <Badge key={s} variant="default">
                      {s}
                    </Badge>
                  ))}
                </CardContent>
              </Card>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
