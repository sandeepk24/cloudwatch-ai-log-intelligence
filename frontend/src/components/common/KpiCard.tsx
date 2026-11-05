import { TrendingDown, TrendingUp, Minus } from "lucide-react";
import { cn } from "@/lib/utils";
import type { KpiMetric } from "@/types/ops";
import { SeverityBadge } from "@/components/ops/SeverityBadge";

interface KpiCardProps {
  metric: KpiMetric;
  className?: string;
}

export function KpiCard({ metric, className }: KpiCardProps) {
  const TrendIcon =
    metric.trend === "up" ? TrendingUp : metric.trend === "down" ? TrendingDown : Minus;

  return (
    <article
      className={cn(
        "rounded-lg border border-border bg-card p-4 shadow-sm transition-colors",
        className
      )}
      aria-label={`${metric.label}: ${metric.value}`}
    >
      <div className="flex items-start justify-between gap-2">
        <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
          {metric.label}
        </p>
        {metric.severity && <SeverityBadge severity={metric.severity} compact />}
      </div>
      <p className="mt-2 text-2xl font-semibold tabular-nums text-foreground">
        {metric.value}
        {metric.unit && (
          <span className="ml-1 text-sm font-normal text-muted-foreground">{metric.unit}</span>
        )}
      </p>
      {metric.deltaPct !== undefined && (
        <p
          className={cn(
            "mt-2 flex items-center gap-1 text-xs",
            metric.deltaPct > 0 ? "text-destructive" : "text-success"
          )}
        >
          <TrendIcon className="h-3.5 w-3.5" aria-hidden />
          <span>{metric.deltaPct > 0 ? "+" : ""}{metric.deltaPct}% vs baseline</span>
        </p>
      )}
    </article>
  );
}
