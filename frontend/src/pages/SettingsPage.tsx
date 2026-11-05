import { useEffect, useState, type ReactNode } from "react";
import { useSettings } from "@/api/queries";
import { Badge } from "@/components/common/Badge";
import { Button } from "@/components/common/Button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/common/Card";
import { Spinner } from "@/components/common/Spinner";
import { Header } from "@/components/layout/Header";
import { ThemeToggle } from "@/components/layout/ThemeToggle";
import { DEMO_ACCOUNTS, DEMO_LOG_GROUPS, DEMO_REGIONS } from "@/demo/data";
import { loadPreferences, savePreferences } from "@/demo/preferences";
import type { WorkspacePreferences as Prefs } from "@/types/ops";

export function SettingsPage() {
  const { data, isLoading, error } = useSettings();
  const [prefs, setPrefs] = useState<Prefs>(() => loadPreferences());
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (!prefs.accounts.length) {
      setPrefs((p) => ({ ...p, accounts: DEMO_ACCOUNTS, regions: DEMO_REGIONS, logGroups: DEMO_LOG_GROUPS }));
    }
  }, [prefs.accounts.length]);

  const persist = () => {
    savePreferences(prefs);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div>
      <Header
        title="Settings"
        description="Workspace scope and query budgets. AWS credentials and Bedrock stay on the backend only."
      >
        <ThemeToggle />
      </Header>
      <div className="grid gap-6 p-6 lg:grid-cols-2 lg:p-8">
        <Card>
          <CardHeader>
            <CardTitle>Backend environment</CardTitle>
            <CardDescription>Read-only server configuration (no secrets).</CardDescription>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Spinner />
            ) : error ? (
              <p className="text-sm text-destructive">{error instanceof Error ? error.message : "Error"}</p>
            ) : (
              <dl className="space-y-3 text-sm">
                <Row label="Application" value={data?.app_name} />
                <Row label="AWS mode" value={data?.aws_mode} />
                <Row label="Region" value={data?.aws_region ?? "default chain"} />
                <Row
                  label="Bedrock"
                  value={
                    <Badge variant={data?.bedrock_configured ? "success" : "outline"}>
                      {data?.bedrock_configured ? "enabled" : "mock/stub"}
                    </Badge>
                  }
                />
              </dl>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Workspace scope</CardTitle>
            <CardDescription>Stored locally in your browser for UI defaults.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4 text-sm">
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={prefs.demoData}
                onChange={(e) => setPrefs({ ...prefs, demoData: e.target.checked })}
              />
              Use synthetic demo data when API is unavailable
            </label>
            <label className="block">
              <span className="font-medium">Query scan budget (bytes)</span>
              <input
                type="number"
                min={1_000_000}
                value={prefs.queryBudgetBytes}
                onChange={(e) =>
                  setPrefs({ ...prefs, queryBudgetBytes: Number(e.target.value) || prefs.queryBudgetBytes })
                }
                className="mt-1 h-10 w-full rounded-md border border-input bg-background px-3"
              />
            </label>
            <label className="block">
              <span className="font-medium">Max log groups per query</span>
              <input
                type="number"
                min={1}
                max={50}
                value={prefs.maxLogGroupsPerQuery}
                onChange={(e) =>
                  setPrefs({ ...prefs, maxLogGroupsPerQuery: Number(e.target.value) || 1 })
                }
                className="mt-1 h-10 w-full rounded-md border border-input bg-background px-3"
              />
            </label>
            <div>
              <p className="font-medium">Accounts</p>
              <p className="mt-1 text-xs text-muted-foreground">{prefs.accounts.join(", ")}</p>
            </div>
            <div>
              <p className="font-medium">Regions</p>
              <p className="mt-1 text-xs text-muted-foreground">{prefs.regions.join(", ")}</p>
            </div>
            <div>
              <p className="font-medium">Log groups ({prefs.logGroups.length})</p>
              <ul className="mt-1 max-h-32 overflow-y-auto font-mono text-[11px] text-muted-foreground">
                {prefs.logGroups.map((g) => (
                  <li key={g}>{g}</li>
                ))}
              </ul>
            </div>
            <Button type="button" onClick={persist}>
              {saved ? "Saved" : "Save workspace"}
            </Button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function Row({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex justify-between gap-4 border-b border-border pb-2 last:border-0">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="font-medium">{value ?? "—"}</dd>
    </div>
  );
}
