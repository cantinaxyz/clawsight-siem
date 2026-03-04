/**
 * @fileoverview ClawSight SIEM module: platform/src/app/api/traces/route.ts.
 */
import { Prisma } from "@prisma/client";
import { NextRequest, NextResponse } from "next/server";
import { buildManagedAgentSqlCondition } from "@/lib/agents/filter";
import { authorizeReadRequest, buildProjectSqlCondition, resolveProjectScope } from "@/lib/auth";
import { prisma } from "@/lib/prisma";
import {
  parseTraceFiltersFromUrl,
  serializeTraceRecord,
  type TraceRecord,
} from "@/lib/traces/query";

export const dynamic = "force-dynamic";

/**
 * Lists traces with execution-style filters and managed-agent scoping.
 */
export async function GET(request: NextRequest) {
  try {
    const unauthorized = authorizeReadRequest(request);
    if (unauthorized) return unauthorized;

    const url = new URL(request.url);
    const filters = parseTraceFiltersFromUrl(url);
    const requestedProjectId = url.searchParams.get("projectId")?.trim() || undefined;
    const scope = resolveProjectScope(request, requestedProjectId);
    if (scope.response) return scope.response;
    const conditions: Prisma.Sql[] = [];

    if (filters.sourceType) {
      conditions.push(Prisma.sql`"sourceType" = ${filters.sourceType}`);
    } else if (!filters.includeSystem) {
      conditions.push(Prisma.sql`"sourceType" <> 'system'`);
    }
    if (filters.status) {
      if (filters.status === "completed") {
        conditions.push(Prisma.sql`"endedAt" IS NOT NULL`);
      } else if (filters.status === "failed") {
        conditions.push(
          Prisma.sql`"endedAt" IS NULL AND ("status" IN ('failed', 'error', 'blocked') OR "errorCount" > 0 OR "blockCount" > 0)`,
        );
      } else if (filters.status === "running") {
        conditions.push(
          Prisma.sql`"endedAt" IS NULL AND NOT ("status" IN ('failed', 'error', 'blocked') OR "errorCount" > 0 OR "blockCount" > 0)`,
        );
      } else {
        conditions.push(Prisma.sql`"status" = ${filters.status}`);
      }
    }
    if (filters.agentKey) {
      const condition = buildManagedAgentSqlCondition({
        agentKey: decodeURIComponent(filters.agentKey),
        projectColumn: Prisma.sql`"projectId"`,
        agentInstanceColumn: Prisma.sql`"agentInstanceId"`,
        sessionIdColumn: Prisma.sql`"openclawSessionId"`,
        openclawAgentColumn: Prisma.sql`"openclawAgentId"`,
        sessionKeyColumn: Prisma.sql`"openclawSessionKey"`,
      });
      if (condition) {
        conditions.push(condition);
      }
    }
    if (filters.search) {
      const needle = `%${filters.search}%`;
      conditions.push(
        Prisma.sql`(
          "traceId" ILIKE ${needle}
          OR COALESCE("openclawSessionKey", '') ILIKE ${needle}
          OR COALESCE("openclawRunId", '') ILIKE ${needle}
          OR COALESCE("requestId", '') ILIKE ${needle}
          OR COALESCE("rootExecutionId", '') ILIKE ${needle}
          OR COALESCE("rootMessageId", '') ILIKE ${needle}
          OR COALESCE("openclawAgentId", '') ILIKE ${needle}
          OR COALESCE("firstAction", '') ILIKE ${needle}
        )`,
      );
    }
    if (scope.projectId) {
      conditions.push(buildProjectSqlCondition(Prisma.sql`"projectId"`, scope.projectId));
    }

    const whereClause =
      conditions.length > 0
        ? Prisma.sql`WHERE ${Prisma.join(conditions, " AND ")}`
        : Prisma.empty;

    const [rows, totals] = await Promise.all([
      prisma.$queryRaw<TraceRecord[]>(Prisma.sql`
        SELECT
          "traceId",
          "sourceType",
          "status",
          "startedAt",
          "endedAt",
          "durationMs",
          "lastEventTs",
          "spanCount",
          "eventCount",
          "errorCount",
          "warnCount",
          "blockCount",
          "maxRiskScore",
          "firstCategory",
          "firstAction",
          "projectId",
          "agentInstanceId",
          "requestId",
          "openclawAgentId",
          "openclawSessionKey",
          "openclawSessionId",
          "openclawRunId",
          "createdAt",
          "updatedAt"
        FROM "Trace"
        ${whereClause}
        ORDER BY "lastEventTs" DESC
        LIMIT ${filters.limit}
      `),
      prisma.$queryRaw<Array<{ count: bigint }>>(Prisma.sql`
        SELECT COUNT(*)::bigint AS "count"
        FROM "Trace"
        ${whereClause}
      `),
    ]);

    return NextResponse.json({
      ok: true,
      total: Number(totals[0]?.count ?? 0n),
      data: rows.map(serializeTraceRecord),
    });
  } catch (err) {
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}
