import type { Envelope } from "@/types/api";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code?: string
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function parseError(res: Response): Promise<string> {
  const body = await res.text().catch(() => "Unknown error");
  try {
    const json = JSON.parse(body) as Envelope<unknown> & { detail?: unknown };
    if (json.error?.message) {
      return json.error.message;
    }
    if (typeof json.detail === "string") {
      return json.detail;
    }
  } catch {
    // raw text is fine
  }
  return body || `API error ${res.status}`;
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE}/api/v1${path}`;
  const headers = new Headers(options?.headers);
  if (!(options?.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const res = await fetch(url, { ...options, headers });
  if (!res.ok) {
    throw new ApiError(await parseError(res), res.status);
  }
  const payload = (await res.json()) as Envelope<T>;
  if (!payload.success || payload.data === null || payload.data === undefined) {
    throw new ApiError(payload.error?.message ?? "Empty API response", res.status, payload.error?.code);
  }
  return payload.data;
}

export const api = {
  get: <T>(path: string) => request<T>(path),
};

export async function getLiveness(): Promise<{ status: string; version: string }> {
  const url = `${API_BASE}/health`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new ApiError(await parseError(res), res.status);
  }
  return res.json() as Promise<{ status: string; version: string }>;
}

export function unwrapEnvelope<T>(payload: Envelope<T>): T {
  if (!payload.success || payload.data === null || payload.data === undefined) {
    throw new ApiError(payload.error?.message ?? "Empty API response", 500, payload.error?.code);
  }
  return payload.data;
}
