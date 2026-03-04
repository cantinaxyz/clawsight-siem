import { describe, expect, it } from "vitest";
import { evaluateDetections } from "@/lib/detection";

describe("evaluateDetections policy modify handling", () => {
  it("emits a policy detection match for modify outcomes", () => {
    const detection = evaluateDetections({
      eventId: "evt-policy-modify",
      ts: new Date("2026-03-04T20:00:00.000Z"),
      severity: "info",
      category: "policy",
      action: "guardrail.decide",
      outcome: "modify",
      outcomeReason: "sanitized suspicious output payload",
      payload: {
        kind: "intent_output",
        action: "modify",
      },
    });

    expect(detection.matches.some((match) => match.ruleId === "policy.modified-action")).toBe(true);
    expect(detection.riskScore).toBeGreaterThanOrEqual(45);
  });

  it("normalizes modified outcome alias into policy modify detection match", () => {
    const detection = evaluateDetections({
      eventId: "evt-policy-modified",
      ts: new Date("2026-03-04T20:00:00.000Z"),
      severity: "info",
      category: "policy",
      action: "guardrail.decide",
      outcome: "modified",
      outcomeReason: null,
    });

    expect(detection.matches.some((match) => match.ruleId === "policy.modified-action")).toBe(true);
  });
});
