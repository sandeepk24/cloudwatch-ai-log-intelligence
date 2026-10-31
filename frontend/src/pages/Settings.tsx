import type { ReactNode } from "react";
import { useSettings } from "@/api/queries";
import { Badge } from "@/components/common/Badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/common/Card";
import { Spinner } from "@/components/common/Spinner";
import { Header } from "@/components/layout/Header";

export function Settings() {
  const { data, isLoading, error } = useSettings();

  return (
    <div>
      <Header
        title="Settings"
        description="Non-secret runtime configuration. AWS credentials never leave the backend process."
      />
      <div className="p-8">
        <Card>
          <CardHeader>
            <CardTitle>Environment</CardTitle>
            <CardDescription>Loaded from .env / process environment. No secrets are returned.</CardDescription>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Spinner />
            ) : error ? (
              <p className="text-sm text-destructive">
                {error instanceof Error ? error.message : "Could not load settings"}
              </p>
            ) : (
              <dl className="space-y-3 text-sm">
                <Row label="Application" value={data?.app_name} />
                <Row label="Version" value={data?.app_version} />
                <Row label="AWS mode" value={data?.aws_mode} />
                <Row label="AWS region" value={data?.aws_region ?? "default credential chain"} />
                <Row
                  label="Mock AWS"
                  value={
                    <Badge variant={data?.aws_use_mock ? "success" : "outline"}>
                      {data?.aws_use_mock ? "enabled" : "live"}
                    </Badge>
                  }
                />
                <Row label="AI provider" value={data?.ai_provider} />
                <Row label="Bedrock model" value={data?.bedrock_model_id} />
                <Row
                  label="Bedrock"
                  value={
                    <Badge variant={data?.bedrock_configured ? "success" : "outline"}>
                      {data?.bedrock_configured ? "enabled" : "stub"}
                    </Badge>
                  }
                />
                <Row
                  label="Strands"
                  value={
                    <Badge variant={data?.strands_configured ? "success" : "outline"}>
                      {data?.strands_configured ? "enabled" : "stub"}
                    </Badge>
                  }
                />
              </dl>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function Row({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-border pb-3 last:border-0 last:pb-0">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="font-medium">{value || "—"}</dd>
    </div>
  );
}
