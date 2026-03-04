/**
 * @fileoverview ClawSight SIEM module: platform/src/app/api/traces/stats/route.ts.
 */
import { Prisma } from "@prisma/client";
import { NextRequest, NextResponse } from "next/server";
import { authorizeReadRequest, buildProjectSqlCondition, resolveProjectScope } from "@/lib/auth";
import { prisma } from "@/lib/prisma";

function parseNonNegativeInt(value: string | null, fallback: number): number {
  if (!value) return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) return fallback;
  return Math.min(parsed, 24 * 30);
}

export async function GET(request: NextRequest) {
  try {
    const unauthorized = authorizeReadRequest(request);
    if (unauthorized) return unauthorized;

    const url = new URL(request.url);
    const requestedProjectId = url.searchParams.get("projectId")?.trim() || undefined;
    const scope = resolveProjectScope(request, requestedProjectId);
    if (scope.response) return scope.response;
    const sinceHours = parseNonNegativeInt(url.searchParams.get("sinceHours"), 24);
    const since = new Date(Date.now() - sinceHours * 60 * 60 * 1000);
    const projectWhere = scope.projectId
      ? Prisma.sql`AND ${buildProjectSqlCondition(Prisma.sql`"projectId"`, scope.projectId)}`
      : Prisma.empty;

    const [statusRows, sourceRows, stageRows] = await Promise.all([
      prisma.$queryRaw<Array<{ status: string; hits: bigint }>>`
        SELECT "status", COUNT(*)::bigint AS "hits"
        FROM "Trace"
        WHERE "lastEventTs" >= ${since}
        ${projectWhere}
        GROUP BY "status"
      `,
      prisma.$queryRaw<Array<{ sourceType: string; hits: bigint }>>`
        SELECT "sourceType", COUNT(*)::bigint AS "hits"
        FROM "Trace"
        WHERE "lastEventTs" >= ${since}
        ${projectWhere}
        GROUP BY "sourceType"
      `,
      prisma.$queryRaw<Array<{ stage: string; hits: bigint }>>`
        SELECT "stage", COUNT(*)::bigint AS "hits"
        FROM "TraceSpan"
        WHERE "ts" >= ${since}
          ${
            scope.projectId
              ? Prisma.sql`AND "traceId" IN (
                  SELECT "traceId" FROM "Trace"
                  WHERE ${buildProjectSqlCondition(Prisma.sql`"projectId"`, scope.projectId)}
                )`
              : Prisma.empty
          }
          AND "status" IN ('error', 'block')
        GROUP BY "stage"
        ORDER BY COUNT(*) DESC
        LIMIT 10
      `,
    ]);

    const byStatus = Object.fromEntries(statusRows.map((row) => [row.status, Number(row.hits)]));
    const bySource = Object.fromEntries(sourceRows.map((row) => [row.sourceType, Number(row.hits)]));
    const totalTraces = Object.values(byStatus).reduce((sum, value) => sum + Number(value || 0), 0);

    return NextResponse.json({
      ok: true,
      sinceHours,
      totalTraces,
      byStatus,
      bySource,
      topFailingStages: stageRows.map((row) => ({ stage: row.stage, hits: Number(row.hits) })),
    });
  } catch (err) {
    const message = String(err);
    if (
      message.toLowerCase().includes("does not exist") &&
      (message.toLowerCase().includes("trace\"") || message.toLowerCase().includes("tracespan\""))
    ) {
      return NextResponse.json({
        ok: true,
        sinceHours: 24,
        totalTraces: 0,
        byStatus: {},
        bySource: {},
        topFailingStages: [],
      });
    }
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
