import type { LogSearchFilters, LogSearchResult } from "@/types/ops";
import { demoLogs } from "./data";

export function searchDemoLogs(filters: LogSearchFilters): LogSearchResult {
  const q = filters.query.trim().toLowerCase();
  let filtered = demoLogs.filter((e) => {
    if (filters.severity !== "all" && e.severity !== filters.severity) return false;
    if (filters.logGroup !== "all" && e.logGroup !== filters.logGroup) return false;
    if (filters.service !== "all" && e.service !== filters.service) return false;
    if (q && !e.message.toLowerCase().includes(q) && !e.logGroup.toLowerCase().includes(q)) {
      return false;
    }
    return true;
  });

  filtered = [...filtered].sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );

  const total = filtered.length;
  const start = (filters.page - 1) * filters.pageSize;
  const entries = filtered.slice(start, start + filters.pageSize);

  return { total, page: filters.page, pageSize: filters.pageSize, entries };
}
