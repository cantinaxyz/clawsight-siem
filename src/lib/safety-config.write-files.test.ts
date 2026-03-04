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
  action: string;
};

describe("applySafetyConfig writeFiles guardrail coverage", () => {
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

  it("generates writeFiles rules for write, edit, and apply_patch tools", async () => {
    const cfg = configFromMode("balanced");
    cfg.actions.writeFiles = "block";

    await applySafetyConfig(cfg);

    const rows = (createManyMock.mock.calls[0]?.[0]?.data ?? []) as PolicyCreateRow[];
    const writeRows = rows.filter((row) =>
      row.name.startsWith("safety:actions:write_files:block:tool:"),
    );

    expect(writeRows).toHaveLength(3);
    expect(writeRows.map((row) => row.toolName).sort()).toEqual([
      "apply_patch",
      "edit",
      "write",
    ]);
    expect(writeRows.every((row) => row.action === "block")).toBe(true);
  });

  it("does not generate writeFiles tool rules when writeFiles is allow", async () => {
    const cfg = configFromMode("balanced");
    cfg.actions.writeFiles = "allow";

    await applySafetyConfig(cfg);

    const rows = (createManyMock.mock.calls[0]?.[0]?.data ?? []) as PolicyCreateRow[];
    const hasWriteFilesRule = rows.some((row) =>
      row.name.startsWith("safety:actions:write_files:"),
    );

    expect(hasWriteFilesRule).toBe(false);
  });
});
