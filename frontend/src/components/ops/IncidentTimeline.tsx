import { Flag } from "lucide-react";
import { SeverityBadge } from "@/components/ops/SeverityBadge";
import type { TimelineEvent } from "@/types/ops";
import { cn } from "@/lib/utils";

interface IncidentTimelineProps {
  events: TimelineEvent[];
  className?: string;
}

export function IncidentTimeline({ events, className }: IncidentTimelineProps) {
  const sorted = [...events].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );

  if (!sorted.length) {
    return <p className="text-sm text-muted-foreground">No timeline events.</p>;
  }

  return (
    <ol className={cn("relative space-y-0 border-l border-border pl-6", className)} aria-label="Incident timeline">
      {sorted.map((ev) => (
        <li key={ev.id} className="relative pb-6 last:pb-0">
          <span
            className="absolute -left-[7px] top-1.5 h-3 w-3 rounded-full border-2 border-primary bg-background"
            aria-hidden
          />
          <div className="flex flex-wrap items-center gap-2">
            <time className="text-xs tabular-nums text-muted-foreground" dateTime={ev.timestamp}>
              {new Date(ev.timestamp).toLocaleString()}
            </time>
            <span className="text-xs font-medium text-primary">{ev.source}</span>
            <SeverityBadge severity={ev.severity} compact />
            {ev.isDeployment && (
              <span className="inline-flex items-center gap-1 text-[10px] uppercase text-warning">
                <Flag className="h-3 w-3" aria-hidden />
                Deploy
              </span>
            )}
          </div>
          <p className="mt-1 text-sm text-foreground">{ev.description}</p>
        </li>
      ))}
    </ol>
  );
}
