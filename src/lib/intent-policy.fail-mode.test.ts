import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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

function configRow(failMode: "fail_open" | "fail_closed") {
  return {
    configKey: "global",
    scopeLevel: "global",
    managedAgentKey: null,
    mode: "enforce",
    llmEnabled: true,
    baselineModel: "gpt-4.1-mini",
    alignmentModel: "gpt-4.1-mini",
    outputModel: "gpt-4.1-mini",
    outputSanitization: true,
    driftWarnThreshold: 35,
    driftBlockThreshold: 70,
    ambiguousLowerBound: 30,
    ambiguousUpperBound: 60,
    signalWeights: null,
    domainClasses: null,
    normalizationRules: null,
    toolScopeMappings: null,
    taskDefaults: null,
    alignmentReliefEnabled: true,
    alignmentReliefThreshold: 85,
    failMode,
  };
}

function executionRow() {
  return {
    executionKey: "agent-1:exec-fail-mode",
    rootExecutionId: "exec-fail-mode",
    projectId: "project-a",
    agentInstanceId: "agent-1",
    managedAgentKey: "inst:project-a:agent-1",
    driftScore: 0,
    expectedScopes: ["network_read"],
    expectedDomains: ["docs.example.com"],
    taskBoundary: "Review trusted docs only.",
    baselinePatched: false,
    baselineVersion: 1,
    baselinePatchedAt: null,
    baselinePatchedBy: null,
    baselinePatchReason: null,
  };
}

describe("evaluateIntentAction failMode enforcement", () => {
  const originalApiKey = process.env.OPENAI_API_KEY;
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    queryRawMock.mockReset();
    executeRawMock.mockReset();
    queryRawMock.mockResolvedValue([]);
    executeRawMock.mockResolvedValue(1);
    process.env.OPENAI_API_KEY = "test-key";

    const fetchMock = vi.fn(async () =>
      new Response("upstream unavailable", {
        status: 503,
        headers: { "content-type": "text/plain" },
      }),
    );
    globalThis.fetch = fetchMock as typeof fetch;
  });

  afterEach(() => {
    process.env.OPENAI_API_KEY = originalApiKey;
    globalThis.fetch = originalFetch;
  });

  it("blocks ambiguous actions in enforce mode when failMode is fail_closed and LLM alignment is unavailable", async () => {
    queryRawMock
      .mockResolvedValueOnce([]) // agent config lookup
      .mockResolvedValueOnce([configRow("fail_closed")]) // global config lookup
      .mockResolvedValueOnce([executionRow()]); // execution lookup

    const decision = await evaluateIntentAction({
      rootExecutionId: "exec-fail-mode",
      agentInstanceId: "agent-1",
      projectId: "project-a",
      toolName: "web_fetch",
      params: {
        primaryUrl: "https://evil-one.example/a",
        backupUrl: "https://evil-two.example/b",
      },
    });

    expect(decision.action).toBe("block");
    expect(decision.reason).toBe("intent policy fail-closed blocked action due to unavailable alignment check");
    expect(decision.signals).toContain("llm.alignment.unavailable");
    expect(decision.signals).toContain("llm.alignment.fail_closed");
  });

  it("keeps fail-open behavior when failMode is fail_open and LLM alignment is unavailable", async () => {
    queryRawMock
      .mockResolvedValueOnce([]) // agent config lookup
      .mockResolvedValueOnce([configRow("fail_open")]) // global config lookup
      .mockResolvedValueOnce([executionRow()]); // execution lookup

    const decision = await evaluateIntentAction({
      rootExecutionId: "exec-fail-mode",
      agentInstanceId: "agent-1",
      projectId: "project-a",
      toolName: "web_fetch",
      params: {
        primaryUrl: "https://evil-one.example/a",
        backupUrl: "https://evil-two.example/b",
      },
    });

    expect(decision.action).toBe("warn");
    expect(decision.reason).toBe("intent policy flagged potential scope drift");
    expect(decision.signals).toContain("llm.alignment.unavailable");
    expect(decision.signals).not.toContain("llm.alignment.fail_closed");
  });
});
