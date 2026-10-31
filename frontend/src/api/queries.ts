import { useQuery } from "@tanstack/react-query";
import { api, getLiveness } from "./client";
import type { AppSettings, CapabilitiesData, HealthData, LivenessResponse } from "@/types/api";

export function useLiveness() {
  return useQuery<LivenessResponse>({
    queryKey: ["liveness"],
    queryFn: getLiveness,
    refetchInterval: 15000,
    retry: 1,
  });
}

export function useHealth() {
  return useQuery<HealthData>({
    queryKey: ["health"],
    queryFn: () => api.get<HealthData>("/health"),
    refetchInterval: 15000,
    retry: 1,
  });
}

export function useCapabilities() {
  return useQuery<CapabilitiesData>({
    queryKey: ["capabilities"],
    queryFn: () => api.get<CapabilitiesData>("/capabilities"),
  });
}

export function useSettings() {
  return useQuery<AppSettings>({
    queryKey: ["settings"],
    queryFn: () => api.get<AppSettings>("/settings"),
  });
}
