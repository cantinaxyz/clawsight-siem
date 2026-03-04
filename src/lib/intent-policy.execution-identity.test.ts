import { beforeEach, describe, expect, it, vi } from "vitest";

const { queryRawMock, executeRawMock } = vi.hoisted(() => ({
  queryRawMock: vi.fn(),
  executeRawMock: vi.fn(),
}));

vi.mock("@/lib/prisma", () => ({
  prisma: {
    $queryRaw: queryRawMock,
    $executeRaw: executeRawMock,
  },
}));

import { evaluateIntentAction, evaluateIntentBaseline } from "@/lib/intent-policy";

type ExecutionRowOverrides = {
  projectId?: string | null;
  managedAgentKey?: string | null;
  expectedScopes?: unknown;
  expectedDomains?: unknown;
};

function makeExecutionRow(overrides: ExecutionRowOverrides = {}) {
  return {
    executionKey: "agent-1:exec-1",
    rootExecutionId: "exec-1",
    projectId: "project-a",
    agentInstanceId: "agent-1",
    managedAgentKey: "inst:project-a:agent-1",
    driftScore: 0,
    expectedScopes: ["filesystem_read", "network_read"],
    expectedDomains: ["docs.example.com"],
    taskBoundary: "summarize release notes",
    baselinePatched: false,
    baselineVersion: 1,
    baselinePatchedAt: null,
    baselinePatchedBy: null,
    baselinePatchReason: null,
    ...overrides,
  };
}

describe("intent baseline identity binding", () => {
  beforeEach(() => {
    queryRawMock.mockReset();
    executeRawMock.mockReset();
    queryRawMock.mockResolvedValue([]);
    executeRawMock.mockResolvedValue(1);
    process.env.OPENAI_API_KEY = "";
  });

  it("reuses existing baseline only when identity matches", async () => {
    queryRawMock
      .mockResolvedValueOnce([]) // agent config lookup
      .mockResolvedValueOnce([]) // global config lookup
      .mockResolvedValueOnce([makeExecutionRow()]); // execution lookup

    const decision = await evaluateIntentBaseline({
      rootExecutionId: "exec-1",
      agentInstanceId: "agent-1",
      projectId: "project-a",
      prompt: "Summarize release notes.",
    });

    expect(decision.reason).toBe("intent_baseline_reused");
    expect(decision.expectedDomains).toContain("docs.example.com");
    expect(executeRawMock).not.toHaveBeenCalled();
  });

  it("recomputes and upserts when stored baseline identity conflicts", async () => {
    queryRawMock
      .mockResolvedValueOnce([]) // agent config lookup
      .mockResolvedValueOnce([]) // global config lookup
      .mockResolvedValueOnce([
        makeExecutionRow({
          projectId: "project-b",
          managedAgentKey: "inst:project-b:agent-1",
          expectedDomains: ["evil.example"],
        }),
      ]); // execution lookup

    const decision = await evaluateIntentBaseline({
      rootExecutionId: "exec-1",
      agentInstanceId: "agent-1",
      projectId: "project-a",
      prompt: "Summarize release notes from docs.example.com",
    });

    expect(decision.reason).toBe("intent_baseline_created");
    expect(decision.signals).toContain("intent.baseline.identity_conflict");
    expect(executeRawMock).toHaveBeenCalledTimes(2);

    const upsertSql = executeRawMock.mock.calls[0]?.[0];
    const upsertText = Array.isArray(upsertSql) ? upsertSql.join(" ") : String(upsertSql);
    expect(upsertText).toContain("\"projectId\" = COALESCE");
    expect(upsertText).toContain("\"managedAgentKey\" = COALESCE");
  });

  it("treats identity-conflicted execution rows as missing baseline for action checks", async () => {
    queryRawMock
      .mockResolvedValueOnce([]) // agent config lookup
      .mockResolvedValueOnce([]) // global config lookup
      .mockResolvedValueOnce([
        makeExecutionRow({
          projectId: "project-b",
          managedAgentKey: "inst:project-b:agent-1",
        }),
      ]); // execution lookup

    const decision = await evaluateIntentAction({
      rootExecutionId: "exec-1",
      agentInstanceId: "agent-1",
      projectId: "project-a",
      toolName: "web_fetch",
      params: { url: "https://docs.example.com/changelog" },
    });

    expect(decision.action).toBe("allow");
    expect(decision.reason).toBe("intent_identity_mismatch");
    expect(decision.signals).toContain("intent.action.identity_mismatch");
    expect(executeRawMock).toHaveBeenCalledTimes(1);
    expect(executeRawMock.mock.calls[0]?.[1]).toBeNull();
  });
});
