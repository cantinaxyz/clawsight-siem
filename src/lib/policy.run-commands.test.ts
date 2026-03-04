import { beforeEach, describe, expect, it, vi } from "vitest";
import type { PolicyRule } from "@prisma/client";

const { findManyMock } = vi.hoisted(() => ({
  findManyMock: vi.fn(),
}));

vi.mock("@/lib/prisma", () => ({
  prisma: {
    policyRule: {
      findMany: findManyMock,
    },
  },
}));

import { evaluateToolDecision } from "@/lib/policy";

function buildPolicyRule(overrides: Partial<PolicyRule> = {}): PolicyRule {
  return {
    id: 1,
    name: "safety:actions:run_commands:default:block",
    scope: "tool",
    scopeLevel: "global",
    managedAgentKey: null,
    action: "block",
    priority: 68,
    enabled: true,
    toolName: "exec",
    commandContains: null,
    channelId: null,
    toContains: null,
    contentContains: null,
    modifyContent: null,
    modifyParams: null,
    reason: "Safety run commands default blocks unmatched execution commands",
    createdAt: new Date("2026-01-01T00:00:00.000Z"),
    updatedAt: new Date("2026-01-01T00:00:00.000Z"),
    ...overrides,
  };
}

describe("evaluateToolDecision runCommands default fallback", () => {
  beforeEach(() => {
    findManyMock.mockReset();
    findManyMock.mockResolvedValue([
      buildPolicyRule({
        id: 2,
        name: "safety:actions:run_commands:allow:git",
        action: "allow",
        priority: 10,
        commandContains: "git",
        reason: "Safety run commands allow-list",
      }),
      buildPolicyRule(),
    ]);
  });

  it("allows explicit allow-listed exec commands before default block fallback", async () => {
    const decision = await evaluateToolDecision({
      toolName: "exec",
      params: { command: "git status" },
    });

    expect(decision.action).toBe("allow");
  });

  it("blocks unmatched exec commands via runCommands default fallback", async () => {
    const decision = await evaluateToolDecision({
      toolName: "exec",
      params: { command: "python script.py" },
    });

    expect(decision.action).toBe("block");
    expect(decision.reason).toContain("default blocks unmatched");
  });

  it("applies exec fallback to execution tool aliases like bash", async () => {
    const decision = await evaluateToolDecision({
      toolName: "bash",
      params: { command: "python script.py" },
    });

    expect(decision.action).toBe("block");
    expect(decision.reason).toContain("default blocks unmatched");
  });
});
