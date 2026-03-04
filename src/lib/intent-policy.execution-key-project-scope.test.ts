import { beforeEach, describe, expect, it, vi } from "vitest";

type ExecutionRow = {
  executionKey: string;
  rootExecutionId: string;
  projectId: string | null;
  agentInstanceId: string | null;
  managedAgentKey: string | null;
  driftScore: number;
  expectedScopes: unknown;
  expectedDomains: unknown;
  taskBoundary: string | null;
  baselinePatched: boolean;
  baselineVersion: number;
  baselinePatchedAt: Date | null;
  baselinePatchedBy: string | null;
  baselinePatchReason: string | null;
};

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

function parseSqlArgs(args: unknown[]): { text: string; values: unknown[] } {
  const [first, ...rest] = args;
  if (first && typeof first === "object") {
    const candidate = first as { strings?: string[]; values?: unknown[] };
    if (Array.isArray(candidate.strings) && Array.isArray(candidate.values)) {
      return { text: candidate.strings.join(" "), values: candidate.values };
    }
  }
  if (Array.isArray(first)) {
    return { text: first.join(" "), values: rest };
  }
  return { text: String(first), values: rest };
}

describe("intent executionKey project scoping", () => {
  let executionStore: Map<string, ExecutionRow>;

  beforeEach(() => {
    queryRawMock.mockReset();
    executeRawMock.mockReset();
    process.env.OPENAI_API_KEY = "";

    executionStore = new Map<string, ExecutionRow>();

    queryRawMock.mockImplementation(async (...args: unknown[]) => {
      const { text, values } = parseSqlArgs(args);

      if (text.includes('FROM "IntentPolicyConfig"')) {
        return [];
      }

      if (text.includes('FROM "ExecutionIntent"') && text.includes('WHERE "executionKey" =')) {
        const key = String(values[0] || "");
        const row = executionStore.get(key);
        return row ? [row] : [];
      }

      return [];
    });

    executeRawMock.mockImplementation(async (...args: unknown[]) => {
      const { text, values } = parseSqlArgs(args);

      if (text.includes('INSERT INTO "ExecutionIntent"')) {
        const executionKey = String(values[0] || "");
        executionStore.set(executionKey, {
          executionKey,
          rootExecutionId: String(values[1] || ""),
          projectId: (values[2] as string | null) ?? null,
          agentInstanceId: (values[3] as string | null) ?? null,
          managedAgentKey: (values[5] as string | null) ?? null,
          driftScore: 0,
          taskBoundary: String(values[10] || ""),
          expectedScopes: typeof values[11] === "string" ? JSON.parse(String(values[11])) : values[11],
          expectedDomains: typeof values[12] === "string" ? JSON.parse(String(values[12])) : values[12],
          baselinePatched: false,
          baselineVersion: 1,
          baselinePatchedAt: null,
          baselinePatchedBy: null,
          baselinePatchReason: null,
        });
        return 1;
      }

      if (text.includes('UPDATE "ExecutionIntent"') && text.includes('SET "driftScore" =')) {
        const drift = Number(values[0] || 0);
        const key = String(values[2] || "");
        const current = executionStore.get(key);
        if (current) {
          executionStore.set(key, { ...current, driftScore: drift });
        }
        return 1;
      }

      return 1;
    });
  });

  it("isolates baseline/action state for same root+agent across different projects", async () => {
    const rootExecutionId = "exec-shared";
    const agentInstanceId = "agent-1";

    const aBaseline = await evaluateIntentBaseline({
      projectId: "project-a",
      rootExecutionId,
      agentInstanceId,
      prompt: "Summarize docs from docs.example.com",
    });
    expect(aBaseline.reason).toBe("intent_baseline_created");

    const bBaseline = await evaluateIntentBaseline({
      projectId: "project-b",
      rootExecutionId,
      agentInstanceId,
      prompt: "Summarize finance notes from finance.yahoo.com",
    });
    expect(bBaseline.reason).toBe("intent_baseline_created");
    expect([...executionStore.keys()].sort()).toEqual([
      "project-a:agent-1:exec-shared",
      "project-b:agent-1:exec-shared",
    ]);

    const aAction = await evaluateIntentAction({
      projectId: "project-a",
      rootExecutionId,
      agentInstanceId,
      toolName: "read",
      params: { path: "README.md" },
    });

    expect(aAction.reason).not.toBe("intent_identity_mismatch");
    expect(aAction.signals).not.toContain("intent.action.identity_mismatch");
  });
});
