import { cn } from "@/lib/utils";

interface StatusIndicatorProps {
  status: "connected" | "disconnected" | "loading";
  label: string;
  detail?: string;
}

export function StatusIndicator({ status, label, detail }: StatusIndicatorProps) {
  return (
    <div className="flex items-center gap-2">
      <span
        className={cn("h-2.5 w-2.5 rounded-full", {
          "bg-success animate-pulse": status === "connected",
          "bg-destructive": status === "disconnected",
          "bg-warning animate-pulse": status === "loading",
        })}
      />
      <span className="text-sm text-foreground">{label}</span>
      {detail && <span className="text-xs text-muted-foreground">({detail})</span>}
    </div>
  );
}
