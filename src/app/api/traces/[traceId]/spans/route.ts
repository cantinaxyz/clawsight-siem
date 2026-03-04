/**
 * @fileoverview ClawSight SIEM module: platform/src/app/api/traces/[traceId]/spans/route.ts.
 */
import { Prisma } from "@prisma/client";
import { NextRequest, NextResponse } from "next/server";
import { authorizeReadRequest, buildProjectSqlCondition, resolveProjectScope } from "@/lib/auth";
import { prisma } from "@/lib/prisma";
import {
  parsePositiveInt,
  serializeTraceSpanRecord,
  type TraceSpanRecord,
} from "@/lib/traces/query";

type ParamsInput = { traceId: string };

async function resolveParams(
  params: ParamsInput | Promise<ParamsInput>,
): Promise<ParamsInput> {
  return Promise.resolve(params);
}

function parseUnsignedInt(value: string | null): number | undefined {
  if (!value) return undefined;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) return undefined;
  return parsed;
}

export const dynamic = "force-dynamic";

/**
 * Streams paginated span slices for a trace using `(ts,id)` cursor semantics.
 */
export async function GET(
  request: NextRequest,
  context: { params: ParamsInput | Promise<ParamsInput> },
) {
  try {
    const unauthorized = authorizeReadRequest(request);
    if (unauthorized) return unauthorized;

    const url = new URL(request.url);
    const requestedProjectId = url.searchParams.get("projectId")?.trim() || undefined;
    const scope = resolveProjectScope(request, requestedProjectId);
    if (scope.response) return scope.response;

    const { traceId } = await resolveParams(context.params);
    const decodedTraceId = decodeURIComponent(String(traceId || "").trim());
    if (!decodedTraceId) {
      return NextResponse.json({ error: "traceId required" }, { status: 400 });
    }

    const limit = parsePositiveInt(url.searchParams.get("limit"), 300, 1200);
    const cursorTs = parseUnsignedInt(url.searchParams.get("cursorTs"));
    const cursorId = parseUnsignedInt(url.searchParams.get("cursorId"));

    const cursorClause =
      cursorTs !== undefined
        ? cursorId !== undefined
          ? Prisma.sql`AND (
              s."ts" > ${new Date(cursorTs)}
              OR (s."ts" = ${new Date(cursorTs)} AND s."id" > ${cursorId})
            )`
          : Prisma.sql`AND s."ts" > ${new Date(cursorTs)}`
        : Prisma.empty;

    const rows = await prisma.$queryRaw<TraceSpanRecord[]>(Prisma.sql`
      SELECT
        s."id",
        s."traceId",
        s."spanId",
        s."parentSpanId",
        s."eventExternalId",
        s."ts",
        s."stage",
        s."sourceType",
        s."status",
        s."category",
        s."action",
        s."severity",
        s."outcome",
        s."outcomeReason",
        s."durationMs",
        s."latencyMs",
        s."errorClass",
        s."errorCode",
        s."toolName",
        s."requestId",
        s."sessionKey",
        s."sessionId",
        s."runId",
        s."openclawAgentId",
        s."riskScore",
        s."payloadSummary",
        e."payloadRedacted" AS "payload",
        e."payloadRedacted" AS "payloadRedacted",
        s."createdAt",
        s."updatedAt"
      FROM "TraceSpan" s
      LEFT JOIN "TelemetryEvent" e ON e."eventId" = s."eventExternalId"
      WHERE s."traceId" = ${decodedTraceId}
      ${
        scope.projectId
          ? Prisma.sql`AND s."traceId" IN (
              SELECT "traceId" FROM "Trace"
              WHERE "traceId" = ${decodedTraceId}
                AND ${buildProjectSqlCondition(Prisma.sql`"projectId"`, scope.projectId)}
            )`
          : Prisma.empty
      }
      ${cursorClause}
      ORDER BY s."ts" ASC, s."id" ASC
      LIMIT ${limit}
    `);

    return NextResponse.json({
      ok: true,
      data: rows.map(serializeTraceSpanRecord),
    });
  } catch (err) {
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}
