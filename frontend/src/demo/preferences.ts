import type { WorkspacePreferences } from "@/types/ops";
import { DEMO_ACCOUNTS, DEMO_LOG_GROUPS, DEMO_REGIONS } from "./data";

const KEY = "cw-aiops-workspace";

const defaults: WorkspacePreferences = {
  demoData: import.meta.env.VITE_USE_DEMO_DATA !== "false",
  accounts: DEMO_ACCOUNTS,
  regions: DEMO_REGIONS,
  logGroups: DEMO_LOG_GROUPS,
  queryBudgetBytes: 10_000_000_000,
  maxLogGroupsPerQuery: 10,
};

export function loadPreferences(): WorkspacePreferences {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return { ...defaults };
    return { ...defaults, ...JSON.parse(raw) };
  } catch {
    return { ...defaults };
  }
}

export function savePreferences(prefs: WorkspacePreferences): void {
  localStorage.setItem(KEY, JSON.stringify(prefs));
}

export function isDemoMode(): boolean {
  return loadPreferences().demoData;
}
