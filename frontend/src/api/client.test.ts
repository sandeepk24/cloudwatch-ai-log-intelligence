import { describe, expect, it } from "vitest";
import { ApiError, unwrapEnvelope } from "./client";
import type { Envelope } from "@/types/api";

describe("unwrapEnvelope", () => {
  it("returns data from a successful envelope", () => {
    const payload: Envelope<{ status: string }> = {
      success: true,
      data: { status: "healthy" },
      error: null,
      meta: { request_id: "req-1", timestamp: "2026-10-30T00:00:00Z" },
    };
    expect(unwrapEnvelope(payload)).toEqual({ status: "healthy" });
  });

  it("throws ApiError when the envelope is unsuccessful", () => {
    const payload: Envelope<null> = {
      success: false,
      data: null,
      error: { code: "internal_error", message: "An unexpected error occurred" },
      meta: { request_id: "req-2", timestamp: "2026-10-30T00:00:00Z" },
    };
    expect(() => unwrapEnvelope(payload)).toThrow(ApiError);
  });
});
