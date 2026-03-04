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

vi.mock("@/lib/agents/filter", () => ({
  buildManagedAgentSqlCondition: vi.fn(() => null),
}));

import { GET } from "@/app/api/traces/route";

describe("GET /api/traces auth enforcement", () => {
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
      new Request("http://localhost:3000/api/traces") as unknown as NextRequest,
    );

    expect(response.status).toBe(401);
    expect(queryRawMock).not.toHaveBeenCalled();
  });

  it("returns traces when request is authorized", async () => {
    queryRawMock
      .mockResolvedValueOnce([
        {
          traceId: "trace-1",
          sourceType: "chat",
          status: "completed",
          startedAt: new Date("2026-03-04T20:00:00.000Z"),
          endedAt: new Date("2026-03-04T20:00:05.000Z"),
          durationMs: 5000,
          lastEventTs: new Date("2026-03-04T20:00:05.000Z"),
          spanCount: 3,
          eventCount: 12,
          errorCount: 0,
          warnCount: 1,
          blockCount: 0,
          maxRiskScore: 35,
          firstCategory: "message",
          firstAction: "user.input",
          projectId: "project-a",
          agentInstanceId: "agent-1",
          requestId: "req-1",
          openclawAgentId: "oc-agent-1",
          openclawSessionKey: "sess-key-1",
          openclawSessionId: "sess-id-1",
          openclawRunId: "run-1",
          createdAt: new Date("2026-03-04T20:00:00.000Z"),
          updatedAt: new Date("2026-03-04T20:00:06.000Z"),
        },
      ])
      .mockResolvedValueOnce([{ count: 1n }]);

    const response = await GET(
      new Request("http://localhost:3000/api/traces?limit=1") as unknown as NextRequest,
    );
    const body = await response.json() as {
      ok: boolean;
      total: number;
      data: Array<{ traceId: string; startedAt: number }>;
    };

    expect(response.status).toBe(200);
    expect(body.ok).toBe(true);
    expect(body.total).toBe(1);
    expect(body.data).toHaveLength(1);
    expect(body.data[0]?.traceId).toBe("trace-1");
    expect(typeof body.data[0]?.startedAt).toBe("number");
    expect(queryRawMock).toHaveBeenCalledTimes(2);
  });
});
