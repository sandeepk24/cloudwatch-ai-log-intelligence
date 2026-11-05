import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { KpiCard } from "./KpiCard";

describe("KpiCard", () => {
  it("renders label and value with accessible name", () => {
    render(<KpiCard metric={{ id: "x", label: "Errors", value: 42, severity: "high" }} />);
    expect(screen.getByLabelText("Errors: 42")).toBeInTheDocument();
  });
});
