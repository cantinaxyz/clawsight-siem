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

import { evaluateIntentAction } from "@/lib/intent-policy";

function makeExecutionRow() {
  return {
    executionKey: "agent-1:exec-capabilities",
    rootExecutionId: "exec-capabilities",
    projectId: "project-a",
    agentInstanceId: "agent-1",
    managedAgentKey: "inst:project-a:agent-1",
    driftScore: 0,
    expectedScopes: ["filesystem_read"],
    expectedDomains: [],
    taskBoundary: "Read and summarize release notes.",
    baselinePatched: false,
    baselineVersion: 1,
    baselinePatchedAt: null,
    baselinePatchedBy: null,
    baselinePatchReason: null,
  };
}

describe("intent tool capability mapping coverage", () => {
  beforeEach(() => {
    queryRawMock.mockReset();
    executeRawMock.mockReset();
    queryRawMock.mockResolvedValue([]);
    executeRawMock.mockResolvedValue(1);
    process.env.OPENAI_API_KEY = "";
  });

  it("applies filesystem_write drift for apply_patch tool actions", async () => {
    queryRawMock
      .mockResolvedValueOnce([]) // agent config lookup
      .mockResolvedValueOnce([]) // global config lookup
      .mockResolvedValueOnce([makeExecutionRow()]); // execution lookup

    const decision = await evaluateIntentAction({
      rootExecutionId: "exec-capabilities",
      agentInstanceId: "agent-1",
      projectId: "project-a",
      toolName: "apply_patch",
      params: {
        path: "README.md",
        patch: "*** Begin Patch\n*** End Patch\n",
      },
    });

    expect(decision.action).toBe("allow");
    expect(decision.scoreDelta).toBeGreaterThan(0);
    expect((decision.signals ?? []).some((signal) => signal.startsWith("scope.mismatch:filesystem_write:"))).toBe(true);
  });

  it("applies execution drift for process tool actions", async () => {
    queryRawMock
      .mockResolvedValueOnce([]) // agent config lookup
      .mockResolvedValueOnce([]) // global config lookup
      .mockResolvedValueOnce([makeExecutionRow()]); // execution lookup

    const decision = await evaluateIntentAction({
      rootExecutionId: "exec-capabilities",
      agentInstanceId: "agent-1",
      projectId: "project-a",
      toolName: "process",
      params: {
        action: "start",
        command: "python worker.py",
      },
    });

    expect(decision.action).toBe("allow");
    expect(decision.scoreDelta).toBeGreaterThan(0);
    expect((decision.signals ?? []).some((signal) => signal.startsWith("scope.mismatch:execution:"))).toBe(true);
  });

  it("applies filesystem_write drift for apply_patch-prefixed tool names", async () => {
    queryRawMock
      .mockResolvedValueOnce([]) // agent config lookup
      .mockResolvedValueOnce([]) // global config lookup
      .mockResolvedValueOnce([makeExecutionRow()]); // execution lookup

    const decision = await evaluateIntentAction({
      rootExecutionId: "exec-capabilities",
      agentInstanceId: "agent-1",
      projectId: "project-a",
      toolName: "apply_patch:workspace",
      params: {
        path: "README.md",
        patch: "*** Begin Patch\n*** End Patch\n",
      },
    });

    expect(decision.action).toBe("allow");
    expect(decision.scoreDelta).toBeGreaterThan(0);
    expect((decision.signals ?? []).some((signal) => signal.startsWith("scope.mismatch:filesystem_write:"))).toBe(true);
  });

  it("applies execution drift for process-prefixed tool names", async () => {
    queryRawMock
      .mockResolvedValueOnce([]) // agent config lookup
      .mockResolvedValueOnce([]) // global config lookup
      .mockResolvedValueOnce([makeExecutionRow()]); // execution lookup

    const decision = await evaluateIntentAction({
      rootExecutionId: "exec-capabilities",
      agentInstanceId: "agent-1",
      projectId: "project-a",
      toolName: "process:start",
      params: {
        action: "start",
        command: "python worker.py",
      },
    });

    expect(decision.action).toBe("allow");
    expect(decision.scoreDelta).toBeGreaterThan(0);
    expect((decision.signals ?? []).some((signal) => signal.startsWith("scope.mismatch:execution:"))).toBe(true);
  });
});
