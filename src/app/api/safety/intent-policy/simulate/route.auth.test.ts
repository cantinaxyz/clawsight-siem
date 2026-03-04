import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  authorizeAdminRequestMock,
  evaluateIntentBaselineMock,
  evaluateIntentActionMock,
  evaluateIntentOutputMock,
  transactionMock,
  intentDecisionDeleteManyMock,
  executionIntentDeleteManyMock,
} = vi.hoisted(() => ({
  authorizeAdminRequestMock: vi.fn(),
  evaluateIntentBaselineMock: vi.fn(),
  evaluateIntentActionMock: vi.fn(),
  evaluateIntentOutputMock: vi.fn(),
  transactionMock: vi.fn(),
  intentDecisionDeleteManyMock: vi.fn(),
  executionIntentDeleteManyMock: vi.fn(),
}));

vi.mock("@/lib/auth", () => ({
  authorizeAdminRequest: authorizeAdminRequestMock,
}));

vi.mock("@/lib/intent-policy", () => ({
  evaluateIntentBaseline: evaluateIntentBaselineMock,
  evaluateIntentAction: evaluateIntentActionMock,
  evaluateIntentOutput: evaluateIntentOutputMock,
}));

vi.mock("@/lib/prisma", () => ({
  prisma: {
    $transaction: transactionMock,
    intentDecision: {
      deleteMany: intentDecisionDeleteManyMock,
    },
    executionIntent: {
      deleteMany: executionIntentDeleteManyMock,
    },
  },
}));

import { POST } from "@/app/api/safety/intent-policy/simulate/route";

describe("POST /api/safety/intent-policy/simulate auth enforcement", () => {
  beforeEach(() => {
    authorizeAdminRequestMock.mockReset();
    evaluateIntentBaselineMock.mockReset();
    evaluateIntentActionMock.mockReset();
    evaluateIntentOutputMock.mockReset();
    transactionMock.mockReset();
    intentDecisionDeleteManyMock.mockReset();
    executionIntentDeleteManyMock.mockReset();

    authorizeAdminRequestMock.mockReturnValue(null);
    evaluateIntentBaselineMock.mockResolvedValue({
      reason: "intent_baseline_created",
      expectedScopes: [],
      expectedDomains: [],
    });
    evaluateIntentActionMock.mockResolvedValue({
      action: "allow",
      scoreDelta: 0,
      driftScore: 0,
      signals: [],
    });
    evaluateIntentOutputMock.mockResolvedValue({
      action: "allow",
      scoreDelta: 0,
      driftScore: 0,
      signals: [],
    });
    intentDecisionDeleteManyMock.mockResolvedValue({ count: 0 });
    executionIntentDeleteManyMock.mockResolvedValue({ count: 0 });
    transactionMock.mockResolvedValue([]);
  });

  it("returns 401 when request is unauthorized", async () => {
    authorizeAdminRequestMock.mockReturnValue(
      Response.json({ error: "Unauthorized" }, { status: 401 }),
    );

    const response = await POST(
      new Request("http://localhost:3000/api/safety/intent-policy/simulate", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ run: "full", task: "test" }),
      }),
    );

    expect(response.status).toBe(401);
    expect(evaluateIntentBaselineMock).not.toHaveBeenCalled();
    expect(evaluateIntentActionMock).not.toHaveBeenCalled();
    expect(evaluateIntentOutputMock).not.toHaveBeenCalled();

    expect(transactionMock).toHaveBeenCalledTimes(1);
    expect(intentDecisionDeleteManyMock).toHaveBeenCalledTimes(1);
    expect(executionIntentDeleteManyMock).toHaveBeenCalledTimes(1);

    const intentDeleteArgs = intentDecisionDeleteManyMock.mock.calls[0]?.[0] as {
      where: { rootExecutionId: string };
    };
    const executionDeleteArgs = executionIntentDeleteManyMock.mock.calls[0]?.[0] as {
      where: { rootExecutionId: string };
    };
    expect(intentDeleteArgs.where.rootExecutionId.startsWith("sim:")).toBe(true);
    expect(executionDeleteArgs.where.rootExecutionId).toBe(intentDeleteArgs.where.rootExecutionId);
  });

  it("runs full simulation when request is authorized", async () => {
    const response = await POST(
      new Request("http://localhost:3000/api/safety/intent-policy/simulate", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          run: "full",
          task: "collect system facts",
          toolName: "exec",
          toolParams: { command: "uname -a" },
          toolOutput: "Linux host",
        }),
      }),
    );

    const body = (await response.json()) as {
      ok: boolean;
      run: string;
      baseline?: { reason: string };
      action?: { action: string };
      output?: { action: string };
    };

    expect(response.status).toBe(200);
    expect(body.ok).toBe(true);
    expect(body.run).toBe("full");
    expect(body.baseline?.reason).toBe("intent_baseline_created");
    expect(body.action?.action).toBe("allow");
    expect(body.output?.action).toBe("allow");

    expect(authorizeAdminRequestMock).toHaveBeenCalledTimes(1);
    expect(evaluateIntentBaselineMock).toHaveBeenCalledTimes(1);
    expect(evaluateIntentActionMock).toHaveBeenCalledTimes(1);
    expect(evaluateIntentOutputMock).toHaveBeenCalledTimes(1);

    const actionInput = evaluateIntentActionMock.mock.calls[0]?.[0] as {
      toolName: string;
      params: Record<string, unknown>;
    };
    const outputInput = evaluateIntentOutputMock.mock.calls[0]?.[0] as {
      toolName: string;
      content: string;
    };
    expect(actionInput.toolName).toBe("exec");
    expect(actionInput.params.command).toBe("uname -a");
    expect(outputInput.toolName).toBe("exec");
    expect(outputInput.content).toBe("Linux host");

    expect(transactionMock).toHaveBeenCalledTimes(1);
    expect(intentDecisionDeleteManyMock).toHaveBeenCalledTimes(1);
    expect(executionIntentDeleteManyMock).toHaveBeenCalledTimes(1);
  });
});
