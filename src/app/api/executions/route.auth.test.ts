import { beforeEach, describe, expect, it, vi } from "vitest";
import type { NextRequest } from "next/server";

const {
  queryRawMock,
  managedAgentFindManyMock,
  authorizeReadRequestMock,
  resolveProjectScopeMock,
} = vi.hoisted(() => ({
  queryRawMock: vi.fn(),
  managedAgentFindManyMock: vi.fn(),
  authorizeReadRequestMock: vi.fn(),
  resolveProjectScopeMock: vi.fn(),
}));

vi.mock("@/lib/prisma", () => ({
  prisma: {
    $queryRaw: queryRawMock,
    managedAgent: {
      findMany: managedAgentFindManyMock,
    },
  },
}));

vi.mock("@/lib/auth", () => ({
  authorizeReadRequest: authorizeReadRequestMock,
  resolveProjectScope: resolveProjectScopeMock,
  buildProjectSqlCondition: vi.fn(() => null),
}));

vi.mock("@/lib/agents/filter", () => ({
  buildManagedAgentSqlCondition: vi.fn(() => null),
}));

import { GET } from "@/app/api/executions/route";

describe("GET /api/executions auth enforcement", () => {
  beforeEach(() => {
    queryRawMock.mockReset();
    managedAgentFindManyMock.mockReset();
    authorizeReadRequestMock.mockReset();
    resolveProjectScopeMock.mockReset();
    authorizeReadRequestMock.mockReturnValue(null);
    resolveProjectScopeMock.mockReturnValue({});
  });

  it("returns 401 when request is unauthorized", async () => {
    authorizeReadRequestMock.mockReturnValue(
      Response.json({ error: "Unauthorized" }, { status: 401 }),
    );

    const response = await GET(
      new Request("http://localhost:3000/api/executions") as unknown as NextRequest,
    );

    expect(response.status).toBe(401);
    expect(resolveProjectScopeMock).not.toHaveBeenCalled();
    expect(queryRawMock).not.toHaveBeenCalled();
    expect(managedAgentFindManyMock).not.toHaveBeenCalled();
  });

  it("returns empty executions when request is authorized", async () => {
    queryRawMock.mockResolvedValueOnce([]);

    const response = await GET(
      new Request("http://localhost:3000/api/executions?limit=5") as unknown as NextRequest,
    );
    const body = await response.json() as { ok: boolean; data: unknown[] };

    expect(response.status).toBe(200);
    expect(body.ok).toBe(true);
    expect(body.data).toEqual([]);
    expect(resolveProjectScopeMock).toHaveBeenCalledTimes(1);
    expect(queryRawMock).toHaveBeenCalledTimes(1);
    expect(managedAgentFindManyMock).not.toHaveBeenCalled();
  });
});
