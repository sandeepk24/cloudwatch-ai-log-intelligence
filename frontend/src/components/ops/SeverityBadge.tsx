import { cn } from "@/lib/utils";
import type { Severity } from "@/types/ops";

const styles: Record<Severity, string> = {
  critical: "bg-destructive/20 text-destructive border-destructive/30",
  high: "bg-warning/20 text-warning border-warning/30",
  medium: "bg-primary/15 text-primary border-primary/25",
  low: "bg-muted text-muted-foreground border-border",
  info: "bg-secondary text-secondary-foreground border-border",
};

interface SeverityBadgeProps {
  severity: Severity;
  compact?: boolean;
  className?: string;
}

export function SeverityBadge({ severity, compact, className }: SeverityBadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded border font-medium uppercase tracking-wide",
        compact ? "px-1.5 py-0.5 text-[10px]" : "px-2 py-0.5 text-xs",
        styles[severity],
        className
      )}
      role="status"
      aria-label={`Severity ${severity}`}
    >
      {severity}
    </span>
  );
}
