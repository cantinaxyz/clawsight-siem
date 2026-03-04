/**
 * @fileoverview ClawSight SIEM module: platform/src/app/api/traces/orphans/route.ts.
 */
import { Prisma } from "@prisma/client";
import { NextRequest, NextResponse } from "next/server";
import { authorizeAdminRequest, resolveProjectScope } from "@/lib/auth";
import { prisma } from "@/lib/prisma";
import {
  parsePositiveInt,
  serializeTraceOrphanRecord,
  type TraceOrphanRecord,
} from "@/lib/traces/query";

export const dynamic = "force-dynamic";

function isMissingTraceOrphanTableError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  const message = err.message.toLowerCase();
  return message.includes("does not exist") && message.includes("traceorphan");
}

/**
 * Lists orphan telemetry rows that could not be attached to a trace.
 */
export async function GET(request: NextRequest) {
  try {
    const unauthorized = authorizeAdminRequest(request);
    if (unauthorized) return unauthorized;

    const scope = resolveProjectScope(request, undefined);
    if (scope.response) return scope.response;
    if (scope.projectId) {
      return NextResponse.json(
        { error: "Trace orphan feed is not project-scoped" },
        { status: 403 },
      );
    }

    const url = new URL(request.url);
    const reason = url.searchParams.get("reason")?.trim() || "";
    const search = url.searchParams.get("search")?.trim() || url.searchParams.get("q")?.trim() || "";
    const limit = parsePositiveInt(url.searchParams.get("limit"), 100, 500);

    const conditions: Prisma.Sql[] = [];
    if (reason) {
      conditions.push(Prisma.sql`"reason" = ${reason}`);
    }
    if (search) {
      const needle = `%${search}%`;
      conditions.push(
        Prisma.sql`(
          COALESCE("eventExternalId", '') ILIKE ${needle}
          OR COALESCE("requestId", '') ILIKE ${needle}
          OR COALESCE("rootExecutionId", '') ILIKE ${needle}
          OR COALESCE("rootMessageId", '') ILIKE ${needle}
          OR COALESCE("traceHint", '') ILIKE ${needle}
          OR COALESCE("openclawSessionKey", '') ILIKE ${needle}
        )`,
      );
    }

    const whereClause =
      conditions.length > 0
        ? Prisma.sql`WHERE ${Prisma.join(conditions, " AND ")}`
        : Prisma.empty;

    const [rows, totals] = await Promise.all([
      prisma.$queryRaw<TraceOrphanRecord[]>(Prisma.sql`
        SELECT
          "id",
          "eventExternalId",
          "eventTs",
          "eventCategory",
          "eventAction",
          "reason",
          "traceHint",
          "requestId",
          "rootExecutionId",
          "rootMessageId",
          "openclawSessionKey",
          NULL::jsonb AS "payload",
          "createdAt",
          "updatedAt"
        FROM "TraceOrphan"
        ${whereClause}
        ORDER BY "createdAt" DESC
        LIMIT ${limit}
      `),
      prisma.$queryRaw<Array<{ count: bigint }>>(Prisma.sql`
        SELECT COUNT(*)::bigint AS "count"
        FROM "TraceOrphan"
        ${whereClause}
      `),
    ]);

    return NextResponse.json({
      ok: true,
      total: Number(totals[0]?.count ?? 0n),
      data: rows.map(serializeTraceOrphanRecord),
    });
  } catch (err) {
    if (isMissingTraceOrphanTableError(err)) {
      return NextResponse.json({ ok: true, total: 0, data: [] });
    }
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}
