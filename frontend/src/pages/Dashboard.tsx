import { useCapabilities, useHealth, useLiveness } from "@/api/queries";
import { Badge } from "@/components/common/Badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/common/Card";
import { Spinner } from "@/components/common/Spinner";
import { Header } from "@/components/layout/Header";
import type { ModuleStatus } from "@/types/api";

export function Dashboard() {
  const { data: liveness, isLoading: livenessLoading, error: livenessError } = useLiveness();
  const { data: health, isLoading, error } = useHealth();
  const { data: capabilities } = useCapabilities();

  return (
    <div>
      <Header
        title="Dashboard"
        description="Foundation health for CloudWatch log intelligence. Ingestion and AI are not wired yet."
      />
      <div className="space-y-6 p-8">
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          <StatusCard
            title="API"
            loading={livenessLoading}
            ok={Boolean(liveness)}
            detail={
              liveness
                ? `v${liveness.version}`
                : livenessError instanceof Error
                  ? livenessError.message
                  : "checking"
            }
          />
          <StatusCard
            title="AWS adapters"
            loading={isLoading}
            ok={Boolean(health)}
            detail={
              health
                ? `${health.aws_mode}${health.aws_region ? ` · ${health.aws_region}` : ""}`
                : error instanceof Error
                  ? error.message
                  : "checking"
            }
          />
          <StatusCard
            title="AI providers"
            loading={isLoading}
            ok={Boolean(health?.bedrock_configured || health?.strands_configured)}
            detail={`${health?.ai_provider ?? "bedrock"} stub`}
          />
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Pipeline modules</CardTitle>
            <CardDescription>
              Each stage is a separate service. This milestone only establishes the boundaries.
            </CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3 md:grid-cols-2">
            <ModuleCard name="Ingestion" module={capabilities?.ingestion} />
            <ModuleCard name="Analytics" module={capabilities?.analytics} />
            <ModuleCard name="Correlation" module={capabilities?.correlation} />
            <ModuleCard name="AI reasoning" module={capabilities?.reasoning} />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function StatusCard({
  title,
  loading,
  ok,
  detail,
}: {
  title: string;
  loading: boolean;
  ok: boolean;
  detail: string;
}) {
  return (
    <Card>
      <CardContent className="p-6">
        <p className="text-sm text-muted-foreground">{title}</p>
        {loading ? (
          <Spinner className="mt-3" />
        ) : (
          <>
            <div className="mt-2">
              <Badge variant={ok ? "success" : "outline"}>{ok ? "ready" : "not configured"}</Badge>
            </div>
            <p className="mt-3 text-xs text-muted-foreground">{detail}</p>
          </>
        )}
      </CardContent>
    </Card>
  );
}

function ModuleCard({ name, module }: { name: string; module?: ModuleStatus }) {
  return (
    <div className="rounded-md border border-border p-4">
      <div className="flex items-center justify-between gap-3">
        <p className="text-sm font-medium">{name}</p>
        <Badge variant="outline">{module?.status ?? "loading"}</Badge>
      </div>
      <p className="mt-2 text-xs text-muted-foreground">{module?.detail ?? "—"}</p>
    </div>
  );
}
