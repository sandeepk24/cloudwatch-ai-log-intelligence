import { describe, expect, it } from "vitest";
import { searchDemoLogs } from "./searchLogs";

describe("searchDemoLogs", () => {
  it("filters by query string", () => {
    const result = searchDemoLogs({
      query: "connection refused",
      severity: "all",
      logGroup: "all",
      service: "all",
      page: 1,
      pageSize: 50,
    });
    expect(result.total).toBeGreaterThan(0);
    expect(result.entries.every((e) => e.message.toLowerCase().includes("connection"))).toBe(true);
  });

  it("paginates results", () => {
    const p1 = searchDemoLogs({
      query: "",
      severity: "all",
      logGroup: "all",
      service: "all",
      page: 1,
      pageSize: 10,
    });
    const p2 = searchDemoLogs({
      query: "",
      severity: "all",
      logGroup: "all",
      service: "all",
      page: 2,
      pageSize: 10,
    });
    expect(p1.entries).toHaveLength(10);
    expect(p1.entries[0]?.id).not.toBe(p2.entries[0]?.id);
  });
});
