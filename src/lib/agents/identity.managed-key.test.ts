import { describe, expect, it } from "vitest";
import { deriveManagedAgentKey, parseManagedAgentKey } from "@/lib/agents/identity";

describe("managed agent key project segment hardening", () => {
  it("sanitizes delimiter characters in project ids during key derivation", () => {
    const key = deriveManagedAgentKey({
      projectId: "victimProject:attackerSuffix",
      agentInstanceId: "agent-123",
    });

    expect(key).toBe("inst:victimProject-attackerSuffix:agent-123");
    expect(key.split(":")).toHaveLength(3);

    const parsed = parseManagedAgentKey(key);
    expect(parsed).toEqual({
      kind: "inst",
      projectId: "victimProject-attackerSuffix",
      value: "agent-123",
    });
  });

  it("normalizes unsafe project tokens when parsing canonical keys", () => {
    const parsed = parseManagedAgentKey("inst:  dev tenant / blue  :agent-1");
    expect(parsed).toEqual({
      kind: "inst",
      projectId: "dev-tenant-blue",
      value: "agent-1",
    });
  });
});
