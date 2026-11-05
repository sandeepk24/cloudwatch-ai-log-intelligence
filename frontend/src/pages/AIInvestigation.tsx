import { useState, type FormEvent } from "react";
import { useInvestigationMutation } from "@/api/opsQueries";
import { Button } from "@/components/common/Button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/common/Card";
import { ErrorState } from "@/components/common/ErrorState";
import { LoadingState } from "@/components/common/LoadingState";
import { Badge } from "@/components/common/Badge";
import { Header } from "@/components/layout/Header";
import { ThemeToggle } from "@/components/layout/ThemeToggle";
import { DEMO_LOG_GROUPS } from "@/demo/data";
import { loadPreferences } from "@/demo/preferences";

export function AIInvestigation() {
  const prefs = loadPreferences();
  const [question, setQuestion] = useState(
    "Why did errors spike after the latest deployment in prod-api?"
  );
  const [logGroups, setLogGroups] = useState<string[]>(prefs.logGroups.slice(0, 3));
  const [preset, setPreset] = useState<"15m" | "1h" | "6h" | "24h">("1h");

  const mutation = useInvestigationMutation();

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    mutation.mutate({
      question,
      logGroupNames: logGroups,
      timeRangePreset: preset,
    });
  };

  const result = mutation.data;

  return (
    <div>
      <Header
        title="AI investigation"
        description="Natural-language troubleshooting via the backend agent. No AWS or Bedrock calls from the browser."
      >
        <ThemeToggle />
      </Header>
      <div className="grid gap-6 p-6 lg:grid-cols-2 lg:p-8">
        <Card>
          <CardHeader>
            <CardTitle>Ask a question</CardTitle>
            <CardDescription>
              The server runs read-only CloudWatch tools and returns proven facts vs hypotheses.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={onSubmit} className="space-y-4">
              <label className="block text-sm">
                <span className="font-medium text-foreground">Troubleshooting question</span>
                <textarea
                  required
                  rows={4}
                  value={question}
                  onChange={(e) => setQuestion(e.target.value)}
                  className="mt-2 w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:ring-2 focus-visible:ring-ring"
                />
              </label>
              <label className="block text-sm">
                <span className="font-medium text-foreground">Time range</span>
                <select
                  value={preset}
                  onChange={(e) => setPreset(e.target.value as typeof preset)}
                  className="mt-2 h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
                >
                  <option value="15m">Last 15 minutes</option>
                  <option value="1h">Last hour</option>
                  <option value="6h">Last 6 hours</option>
                  <option value="24h">Last 24 hours</option>
                </select>
              </label>
              <fieldset>
                <legend className="text-sm font-medium">Log groups in scope</legend>
                <div className="mt-2 max-h-40 space-y-1 overflow-y-auto rounded-md border border-border p-2">
                  {DEMO_LOG_GROUPS.map((g) => (
                    <label key={g} className="flex items-center gap-2 text-xs">
                      <input
                        type="checkbox"
                        checked={logGroups.includes(g)}
                        onChange={(e) => {
                          setLogGroups((prev) =>
                            e.target.checked ? [...prev, g] : prev.filter((x) => x !== g)
                          );
                        }}
                      />
                      <span className="font-mono">{g}</span>
                    </label>
                  ))}
                </div>
              </fieldset>
              <Button type="submit" disabled={mutation.isPending || logGroups.length === 0}>
                {mutation.isPending ? "Investigating…" : "Run investigation"}
              </Button>
            </form>
          </CardContent>
        </Card>

        <div className="space-y-4">
          {mutation.isPending && <LoadingState label="Agent querying CloudWatch (read-only)…" />}
          {mutation.isError && (
            <ErrorState
              message={mutation.error instanceof Error ? mutation.error.message : "Investigation failed"}
              onRetry={() => mutation.reset()}
            />
          )}
          {result && !mutation.isPending && (
            <>
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Executive summary</CardTitle>
                  <CardDescription>ID: {result.investigationId}</CardDescription>
                </CardHeader>
                <CardContent className="text-sm leading-relaxed">{result.executiveSummary}</CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Proven facts</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2 text-sm">
                  {result.provenFacts.map((f) => (
                    <div key={f.id} className="rounded-md border border-border p-3">
                      <Badge variant="success" className="mb-2">
                        {f.sourceTool}
                      </Badge>
                      <p>{f.statement}</p>
                    </div>
                  ))}
                </CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Hypotheses</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {result.hypotheses.map((h) => (
                    <div key={h.rank} className="rounded-md border border-border p-3 text-sm">
                      <p className="font-medium">
                        #{h.rank} {h.title}
                      </p>
                      <Badge variant="outline" className="mt-2">
                        {h.evidenceStrength}
                      </Badge>
                      <p className="mt-2 text-muted-foreground">{h.description}</p>
                      {h.causationCaveat && (
                        <p className="mt-2 text-xs text-warning">{h.causationCaveat}</p>
                      )}
                    </div>
                  ))}
                </CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Tool trace</CardTitle>
                </CardHeader>
                <CardContent className="space-y-1 text-xs font-mono">
                  {result.toolCalls.map((t, i) => (
                    <p key={i} className={t.success ? "text-foreground" : "text-destructive"}>
                      {t.toolName}: {t.summary}
                    </p>
                  ))}
                </CardContent>
              </Card>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
