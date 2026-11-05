import { ChevronDown, ChevronRight, Copy } from "lucide-react";
import { useState } from "react";
import { Button } from "@/components/common/Button";
import { SeverityBadge } from "@/components/ops/SeverityBadge";
import type { LogEntry } from "@/types/ops";
import { cn } from "@/lib/utils";

interface LogEvidencePanelProps {
  entry: LogEntry;
  defaultOpen?: boolean;
}

export function LogEvidencePanel({ entry, defaultOpen = false }: LogEvidencePanelProps) {
  const [open, setOpen] = useState(defaultOpen);

  const copyPtr = () => {
    if (entry.ptr) void navigator.clipboard.writeText(entry.ptr);
  };

  return (
    <div className="rounded-md border border-border bg-card text-sm">
      <button
        type="button"
        className="flex w-full items-start gap-3 px-4 py-3 text-left hover:bg-accent/40"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
      >
        {open ? (
          <ChevronDown className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
        ) : (
          <ChevronRight className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
        )}
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={entry.severity} compact />
            <time className="text-xs tabular-nums text-muted-foreground" dateTime={entry.timestamp}>
              {new Date(entry.timestamp).toLocaleString()}
            </time>
            <span className="truncate text-xs text-primary">{entry.logGroup}</span>
          </div>
          <p className={cn("mt-1 text-foreground", !open && "line-clamp-1")}>{entry.message}</p>
        </div>
      </button>
      {open && (
        <div className="border-t border-border px-4 py-3 text-xs text-muted-foreground">
          <dl className="grid gap-2 sm:grid-cols-2">
            <div>
              <dt className="font-medium text-foreground">Service</dt>
              <dd>{entry.service}</dd>
            </div>
            <div>
              <dt className="font-medium text-foreground">Log stream</dt>
              <dd className="font-mono">{entry.logStream ?? "—"}</dd>
            </div>
            <div className="sm:col-span-2">
              <dt className="font-medium text-foreground">Evidence pointer</dt>
              <dd className="mt-1 flex items-center gap-2 font-mono text-[11px] break-all">
                {entry.ptr ?? "—"}
                {entry.ptr && (
                  <Button type="button" variant="ghost" size="sm" onClick={copyPtr} aria-label="Copy pointer">
                    <Copy className="h-3.5 w-3.5" />
                  </Button>
                )}
              </dd>
            </div>
          </dl>
        </div>
      )}
    </div>
  );
}
