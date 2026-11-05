import { Search } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

interface FilterBarProps {
  query: string;
  onQueryChange: (v: string) => void;
  children?: ReactNode;
  className?: string;
  searchLabel?: string;
}

export function FilterBar({
  query,
  onQueryChange,
  children,
  className,
  searchLabel = "Search logs",
}: FilterBarProps) {
  return (
    <div
      className={cn(
        "flex flex-col gap-3 rounded-lg border border-border bg-card p-4 lg:flex-row lg:items-end lg:justify-between",
        className
      )}
      role="search"
    >
      <label className="relative block min-w-[240px] flex-1">
        <span className="sr-only">{searchLabel}</span>
        <Search
          className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground"
          aria-hidden
        />
        <input
          type="search"
          value={query}
          onChange={(e) => onQueryChange(e.target.value)}
          placeholder="Filter by message or log group…"
          className="h-10 w-full rounded-md border border-input bg-background pl-10 pr-3 text-sm text-foreground placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        />
      </label>
      {children && <div className="flex flex-wrap items-center gap-2">{children}</div>}
    </div>
  );
}
