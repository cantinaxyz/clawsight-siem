import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  findUniqueMock,
  transactionMock,
  txQueryRawMock,
  txExecutionIntentFindManyMock,
  txExecutionIntentDeleteManyMock,
  txExecuteRawMock,
  txIntentDecisionDeleteManyMock,
  txPolicyRuleDeleteManyMock,
  txIntentPolicyConfigDeleteManyMock,
  txManagedAgentDeleteMock,
} = vi.hoisted(() => ({
  findUniqueMock: vi.fn(),
  transactionMock: vi.fn(),
  txQueryRawMock: vi.fn(),
  txExecutionIntentFindManyMock: vi.fn(),
  txExecutionIntentDeleteManyMock: vi.fn(),
  txExecuteRawMock: vi.fn(),
  txIntentDecisionDeleteManyMock: vi.fn(),
  txPolicyRuleDeleteManyMock: vi.fn(),
  txIntentPolicyConfigDeleteManyMock: vi.fn(),
  txManagedAgentDeleteMock: vi.fn(),
}));

vi.mock("@/lib/prisma", () => ({
  prisma: {
    managedAgent: {
      findUnique: findUniqueMock,
    },
    $transaction: transactionMock,
  },
}));

import { deleteManagedAgentAndData } from "@/lib/agents/repository";

describe("deleteManagedAgentAndData project scoping", () => {
  beforeEach(() => {
    findUniqueMock.mockReset();
    transactionMock.mockReset();
    txQueryRawMock.mockReset();
    txExecutionIntentFindManyMock.mockReset();
    txExecutionIntentDeleteManyMock.mockReset();
    txExecuteRawMock.mockReset();
    txIntentDecisionDeleteManyMock.mockReset();
    txPolicyRuleDeleteManyMock.mockReset();
    txIntentPolicyConfigDeleteManyMock.mockReset();
    txManagedAgentDeleteMock.mockReset();

    txQueryRawMock.mockResolvedValue([]);
    txExecutionIntentFindManyMock.mockResolvedValue([]);
    txExecutionIntentDeleteManyMock.mockResolvedValue({ count: 0 });
    txExecuteRawMock.mockResolvedValue(0);
    txIntentDecisionDeleteManyMock.mockResolvedValue({ count: 0 });
    txPolicyRuleDeleteManyMock.mockResolvedValue({ count: 0 });
    txIntentPolicyConfigDeleteManyMock.mockResolvedValue({ count: 0 });
    txManagedAgentDeleteMock.mockResolvedValue({ count: 1 });

    transactionMock.mockImplementation(async (input: unknown) => {
      const tx = {
        $queryRaw: txQueryRawMock,
        executionIntent: {
          findMany: txExecutionIntentFindManyMock,
          deleteMany: txExecutionIntentDeleteManyMock,
        },
        $executeRaw: txExecuteRawMock,
        intentDecision: {
          deleteMany: txIntentDecisionDeleteManyMock,
        },
        policyRule: {
          deleteMany: txPolicyRuleDeleteManyMock,
        },
        intentPolicyConfig: {
          deleteMany: txIntentPolicyConfigDeleteManyMock,
        },
        managedAgent: {
          delete: txManagedAgentDeleteMock,
        },
      };
      if (typeof input === "function") {
        return await (input as (arg: typeof tx) => Promise<unknown>)(tx);
      }
      return [];
    });
  });

  it("uses managed-agent row projectId as authoritative cleanup scope", async () => {
    const craftedKey = "inst:victimProject:attackerSuffix:agent-1";
    findUniqueMock.mockResolvedValue({
      id: 1,
      agentKey: craftedKey,
      projectId: "safe-project",
    });

    await deleteManagedAgentAndData(craftedKey);

    expect(txExecutionIntentFindManyMock).toHaveBeenCalledTimes(1);
    const where = txExecutionIntentFindManyMock.mock.calls[0]?.[0]?.where as {
      AND: Array<Record<string, unknown>>;
    };

    expect(where.AND[0]).toEqual({ projectId: "safe-project" });
    expect(where.AND[1]).toEqual({
      OR: [
        { managedAgentKey: craftedKey },
        { agentInstanceId: { in: ["attackerSuffix:agent-1"] } },
      ],
    });
  });
});
