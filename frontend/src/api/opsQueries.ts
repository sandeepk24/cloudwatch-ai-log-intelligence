import { useMutation, useQuery } from "@tanstack/react-query";
import {
  fetchIncidents,
  fetchOverview,
  fetchTrends,
  runInvestigation,
  searchLogs,
} from "./opsClient";
import type { InvestigationRequest, LogSearchFilters } from "@/types/ops";

export function useOverview() {
  return useQuery({
    queryKey: ["ops", "overview"],
    queryFn: fetchOverview,
    refetchInterval: 60_000,
  });
}

export function useLogSearch(filters: LogSearchFilters) {
  return useQuery({
    queryKey: ["ops", "logs", filters],
    queryFn: () => searchLogs(filters),
    placeholderData: (prev) => prev,
  });
}

export function useIncidents() {
  return useQuery({
    queryKey: ["ops", "incidents"],
    queryFn: fetchIncidents,
  });
}

export function useTrends() {
  return useQuery({
    queryKey: ["ops", "trends"],
    queryFn: fetchTrends,
  });
}

export function useInvestigationMutation() {
  return useMutation({
    mutationFn: (req: InvestigationRequest) => runInvestigation(req),
  });
}
