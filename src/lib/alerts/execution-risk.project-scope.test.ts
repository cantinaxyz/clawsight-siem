import type { Prisma } from "@prisma/client";
import { describe, expect, it, vi } from "vitest";
import { buildExecutionRiskAlerts, type ExecutionRiskSignal } from "@/lib/alerts/execution-risk";

function makeSignal(input: Partial<ExecutionRiskSignal> = {}): ExecutionRiskSignal {
  return {
    ts: new Date("2026-03-04T18:00:00.000Z"),
    eventId: "evt-1",
    spanId: "sp-1",
    executionId: "exec-123",
    rootExecutionId: "exec-123",
    projectId: "project-a",
    agentInstanceId: "agent-1",
    openclawAgentId: "oc-1",
    openclawSessionKey: "sess-1",
    requestId: "req-1",
    triggerType: "user",
    category: "policy_violation",
    alertType: "policy_block",
    ruleId: "rule-1",
    ruleName: "Rule One",
    ruleCategory: "execution",
    ruleDescription: "desc",
    ruleSeverity: "high",
    eventCategory: "policy",
    eventAction: "tool.block",
    eventOutcome: "block",
    outcomeReason: "blocked",
    riskScore: 85,
    driftScore: null,
    toolName: "web_fetch",
    domain: "example.com",
    ...input,
  };
}

function makeTx() {
  const findMany = vi.fn().mockResolvedValue([]);
  const upsert = vi.fn().mockResolvedValue(undefined);
  return {
    tx: {
      executionRiskState: {
        findMany,
        upsert,
      },
    } as unknown as Prisma.TransactionClient,
    findMany,
    upsert,
  };
}

describe("buildExecutionRiskAlerts project-scoped identity", () => {
  it("does not merge same execution/category across different projects", async () => {
    const { tx, upsert } = makeTx();
    const alerts = await buildExecutionRiskAlerts(tx, [
      makeSignal({ eventId: "evt-a", projectId: "project-a" }),
      makeSignal({ eventId: "evt-b", projectId: "project-b" }),
    ]);

    expect(upsert).toHaveBeenCalledTimes(2);
    const projectKeys = upsert.mock.calls.map(
      (call) => call[0]?.where?.projectId_executionId_category?.projectId,
    );
    expect(projectKeys.sort()).toEqual(["project-a", "project-b"]);

    const alertKeys = alerts.map((item) => item.alertKey).sort();
    expect(alertKeys).toEqual([
      "exec:project-a:exec-123:policy_violation:high",
      "exec:project-b:exec-123:policy_violation:high",
    ]);
    expect(alerts.every((item) => item.projectId === "project-a" || item.projectId === "project-b")).toBe(true);
  });

  it("normalizes missing project ids into default scope", async () => {
    const { tx, upsert } = makeTx();
    const alerts = await buildExecutionRiskAlerts(tx, [
      makeSignal({ eventId: "evt-a", projectId: null }),
      makeSignal({ eventId: "evt-b", projectId: "" }),
    ]);

    expect(upsert).toHaveBeenCalledTimes(1);
    expect(upsert.mock.calls[0]?.[0]?.where?.projectId_executionId_category?.projectId).toBe("default");
    expect(alerts).toHaveLength(1);
    expect(alerts[0]?.alertKey).toBe("exec:default:exec-123:policy_violation:high");
    expect(alerts[0]?.projectId).toBe("default");
  });
});
