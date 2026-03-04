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

import { evaluateMessageDecision, evaluateToolDecision } from "@/lib/policy";

function buildPolicyRule(overrides: Partial<PolicyRule> = {}): PolicyRule {
  return {
    id: 1,
    name: "test:rule",
    scope: "domain",
    scopeLevel: "global",
    managedAgentKey: null,
    action: "block",
    priority: 1,
    enabled: true,
    toolName: null,
    commandContains: null,
    channelId: null,
    toContains: null,
    contentContains: "evil.example.com",
    modifyContent: null,
    modifyParams: null,
    reason: "Blocked obfuscated destination",
    createdAt: new Date("2026-01-01T00:00:00.000Z"),
    updatedAt: new Date("2026-01-01T00:00:00.000Z"),
    ...overrides,
  };
}

describe("policy target extraction obfuscation handling", () => {
  beforeEach(() => {
    findManyMock.mockReset();
  });

  it("blocks hxxps + [.] obfuscated domains in tool params", async () => {
    findManyMock.mockResolvedValue([
      buildPolicyRule({
        scope: "domain",
        contentContains: "evil.example.com",
      }),
    ]);

    const decision = await evaluateToolDecision({
      toolName: "web_fetch",
      params: {
        url: "hxxps://evil[.]example[.]com/path",
      },
    });

    expect(decision.action).toBe("block");
    expect(decision.reason).toContain("Blocked obfuscated destination");
  });

  it("blocks 'dot' tokenized domains in message content", async () => {
    findManyMock.mockResolvedValue([
      buildPolicyRule({
        scope: "domain",
        contentContains: "evil.example.com",
      }),
    ]);

    const decision = await evaluateMessageDecision({
      content: "please send to hxxp://evil dot example dot com right now",
      to: "ops",
      channelId: "alerts",
    });

    expect(decision.action).toBe("block");
    expect(decision.reason).toContain("Blocked obfuscated destination");
  });

  it("blocks hxxp + [.] obfuscated direct IPv4 targets", async () => {
    findManyMock.mockResolvedValue([
      buildPolicyRule({
        scope: "ip",
        contentContains: null,
        reason: "Blocked direct IP navigation",
      }),
    ]);

    const decision = await evaluateToolDecision({
      toolName: "web_fetch",
      params: {
        url: "hxxp://169[.]254[.]169[.]254/latest/meta-data",
      },
    });

    expect(decision.action).toBe("block");
    expect(decision.reason).toContain("direct IP");
  });
});
