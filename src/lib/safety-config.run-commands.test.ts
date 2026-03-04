import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  deleteManyMock,
  createMock,
  createManyMock,
  transactionMock,
  loadIntentPolicyConfigMock,
  saveIntentPolicyConfigMock,
} = vi.hoisted(() => ({
  deleteManyMock: vi.fn(),
  createMock: vi.fn(),
  createManyMock: vi.fn(),
  transactionMock: vi.fn(),
  loadIntentPolicyConfigMock: vi.fn(),
  saveIntentPolicyConfigMock: vi.fn(),
}));

vi.mock("@/lib/prisma", () => ({
  prisma: {
    $transaction: transactionMock,
  },
}));

vi.mock("@/lib/intent-policy", () => ({
  loadIntentPolicyConfig: loadIntentPolicyConfigMock,
  saveIntentPolicyConfig: saveIntentPolicyConfigMock,
}));

import { applySafetyConfig, configFromMode } from "@/lib/safety-config";

type PolicyCreateRow = {
  name: string;
  toolName: string | null;
  commandContains: string | null;
  action: string;
};

describe("applySafetyConfig runCommands default behavior", () => {
  beforeEach(() => {
    deleteManyMock.mockReset();
    createMock.mockReset();
    createManyMock.mockReset();
    transactionMock.mockReset();
    loadIntentPolicyConfigMock.mockReset();
    saveIntentPolicyConfigMock.mockReset();

    transactionMock.mockImplementation(async (callback: (tx: unknown) => unknown) =>
      callback({
        policyRule: {
          deleteMany: deleteManyMock,
          create: createMock,
          createMany: createManyMock,
        },
      }),
    );
    deleteManyMock.mockResolvedValue({ count: 0 });
    createMock.mockResolvedValue({ id: 1 });
    createManyMock.mockResolvedValue({ count: 1 });
    loadIntentPolicyConfigMock.mockResolvedValue(configFromMode("balanced").intentPolicy);
    saveIntentPolicyConfigMock.mockResolvedValue(undefined);
  });

  it("generates default exec block rule when runCommands is block", async () => {
    const cfg = configFromMode("balanced");
    cfg.actions.runCommands = "block";
    cfg.actions.allowedCommands = ["git"];

    await applySafetyConfig(cfg);

    const rows = (createManyMock.mock.calls[0]?.[0]?.data ?? []) as PolicyCreateRow[];
    const fallbackRule = rows.find((row) =>
      row.name === "safety:actions:run_commands:default:block",
    );

    expect(fallbackRule).toMatchObject({
      toolName: "exec",
      commandContains: null,
      action: "block",
    });
    expect(
      rows.some((row) =>
        row.name === "safety:actions:run_commands:allow:git" &&
        row.toolName === "exec" &&
        row.commandContains === "git",
      ),
    ).toBe(true);
  });

  it("does not generate default exec rule when runCommands is allow", async () => {
    const cfg = configFromMode("balanced");
    cfg.actions.runCommands = "allow";

    await applySafetyConfig(cfg);

    const rows = (createManyMock.mock.calls[0]?.[0]?.data ?? []) as PolicyCreateRow[];
    const hasFallback = rows.some((row) =>
      row.name.startsWith("safety:actions:run_commands:default:"),
    );

    expect(hasFallback).toBe(false);
  });
});
