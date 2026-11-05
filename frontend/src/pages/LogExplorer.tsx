import { useMemo, useState } from "react";
import { useLogSearch } from "@/api/opsQueries";
import { EmptyState } from "@/components/common/EmptyState";
import { ErrorState } from "@/components/common/ErrorState";
import { LoadingState } from "@/components/common/LoadingState";
import { Pagination } from "@/components/common/Pagination";
import { FilterBar } from "@/components/ops/FilterBar";
import { LogEvidencePanel } from "@/components/ops/LogEvidencePanel";
import { Header } from "@/components/layout/Header";
import { ThemeToggle } from "@/components/layout/ThemeToggle";
import { DEMO_LOG_GROUPS } from "@/demo/data";
import type { LogSearchFilters, Severity } from "@/types/ops";

const PAGE_SIZE = 15;

export function LogExplorer() {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [logGroup, setLogGroup] = useState("all");
  const [page, setPage] = useState(1);

  const filters: LogSearchFilters = useMemo(
    () => ({
      query,
      severity,
      logGroup,
      service: "all",
      page,
      pageSize: PAGE_SIZE,
    }),
    [query, severity, logGroup, page]
  );

  const { data, isLoading, error, refetch, isFetching } = useLogSearch(filters);

  return (
    <div>
      <Header title="Log explorer" description="Search and filter CloudWatch log evidence (read-only via backend).">
        <ThemeToggle />
      </Header>
      <div className="space-y-4 p-6 lg:p-8">
        <FilterBar query={query} onQueryChange={(v) => { setQuery(v); setPage(1); }}>
          <select
            aria-label="Severity filter"
            value={severity}
            onChange={(e) => { setSeverity(e.target.value as Severity | "all"); setPage(1); }}
            className="h-10 rounded-md border border-input bg-background px-3 text-sm"
          >
            <option value="all">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
          <select
            aria-label="Log group filter"
            value={logGroup}
            onChange={(e) => { setLogGroup(e.target.value); setPage(1); }}
            className="h-10 max-w-xs rounded-md border border-input bg-background px-3 text-sm"
          >
            <option value="all">All log groups</option>
            {DEMO_LOG_GROUPS.map((g) => (
              <option key={g} value={g}>
                {g}
              </option>
            ))}
          </select>
        </FilterBar>

        {isLoading && <LoadingState label="Searching logs…" />}
        {error && !isLoading && (
          <ErrorState message={error instanceof Error ? error.message : "Search failed"} onRetry={() => refetch()} />
        )}
        {data && !isLoading && data.entries.length === 0 && (
          <EmptyState title="No matching logs" description="Try broadening filters or clearing the search query." />
        )}
        {data && data.entries.length > 0 && (
          <>
            {isFetching && !isLoading && (
              <p className="text-xs text-muted-foreground" aria-live="polite">
                Refreshing…
              </p>
            )}
            <div className="space-y-2">
              {data.entries.map((e, i) => (
                <LogEvidencePanel key={e.id} entry={e} defaultOpen={i === 0 && page === 1} />
              ))}
            </div>
            <Pagination
              page={data.page}
              pageSize={data.pageSize}
              total={data.total}
              onPageChange={setPage}
            />
          </>
        )}
      </div>
    </div>
  );
}
