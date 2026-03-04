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
    name: "safety:internet:block_direct_ip",
    scope: "ip",
    scopeLevel: "global",
    managedAgentKey: null,
    action: "block",
    priority: 880,
    enabled: true,
    toolName: null,
    commandContains: null,
    channelId: null,
    toContains: null,
    contentContains: null,
    modifyContent: null,
    modifyParams: null,
    reason: "Safety internet policy blocks direct IP navigation",
    createdAt: new Date("2026-01-01T00:00:00.000Z"),
    updatedAt: new Date("2026-01-01T00:00:00.000Z"),
    ...overrides,
  };
}

describe("evaluateToolDecision IPv6 literal target extraction", () => {
  beforeEach(() => {
    findManyMock.mockReset();
    findManyMock.mockResolvedValue([buildPolicyRule()]);
  });

  it("blocks bracketed IPv6 literal URLs for ip-scoped block rules", async () => {
    const decision = await evaluateToolDecision({
      toolName: "web_fetch",
      params: { url: "http://[::1]/" },
    });

    expect(decision.action).toBe("block");
    expect(decision.reason).toContain("direct IP");
  });

  it("blocks IPv4-mapped IPv6 literal URLs for ip-scoped block rules", async () => {
    const decision = await evaluateToolDecision({
      toolName: "web_fetch",
      params: { url: "http://[::ffff:169.254.169.254]/latest/meta-data" },
    });

    expect(decision.action).toBe("block");
    expect(decision.reason).toContain("direct IP");
  });
});
