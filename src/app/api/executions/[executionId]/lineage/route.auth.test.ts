import { beforeEach, describe, expect, it, vi } from "vitest";
import type { NextRequest } from "next/server";

const {
  queryRawMock,
  authorizeReadRequestMock,
  resolveProjectScopeMock,
} = vi.hoisted(() => ({
  queryRawMock: vi.fn(),
  authorizeReadRequestMock: vi.fn(),
  resolveProjectScopeMock: vi.fn(),
}));

vi.mock("@/lib/prisma", () => ({
  prisma: {
    $queryRaw: queryRawMock,
  },
}));

vi.mock("@/lib/auth", () => ({
  authorizeReadRequest: authorizeReadRequestMock,
  resolveProjectScope: resolveProjectScopeMock,
  buildProjectSqlCondition: vi.fn(() => null),
}));

import { GET } from "@/app/api/executions/[executionId]/lineage/route";

describe("GET /api/executions/:executionId/lineage auth enforcement", () => {
  beforeEach(() => {
    queryRawMock.mockReset();
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
      new Request("http://localhost:3000/api/executions/trace-1/lineage") as unknown as NextRequest,
      { params: { executionId: "trace-1" } },
    );

    expect(response.status).toBe(401);
    expect(resolveProjectScopeMock).not.toHaveBeenCalled();
    expect(queryRawMock).not.toHaveBeenCalled();
  });

  it("returns 404 when authorized request targets unknown execution", async () => {
    queryRawMock.mockResolvedValueOnce([]);

    const response = await GET(
      new Request("http://localhost:3000/api/executions/trace-1/lineage") as unknown as NextRequest,
      { params: { executionId: "trace-1" } },
    );
    const body = await response.json() as { ok: boolean; error: string };

    expect(response.status).toBe(404);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("execution not found");
    expect(resolveProjectScopeMock).toHaveBeenCalledTimes(1);
    expect(queryRawMock).toHaveBeenCalledTimes(1);
  });
});
