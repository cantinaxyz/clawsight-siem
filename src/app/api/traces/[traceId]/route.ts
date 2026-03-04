/**
 * @fileoverview ClawSight SIEM module: platform/src/app/api/traces/[traceId]/route.ts.
 */
import { Prisma } from "@prisma/client";
import { NextRequest, NextResponse } from "next/server";
import { authorizeReadRequest, buildProjectSqlCondition, resolveProjectScope } from "@/lib/auth";
import { prisma } from "@/lib/prisma";
import {
  parsePositiveInt,
  serializeTraceRecord,
  serializeTraceSpanRecord,
  type TraceRecord,
  type TraceSpanRecord,
} from "@/lib/traces/query";

type ParamsInput = { traceId: string };

async function resolveParams(
  params: ParamsInput | Promise<ParamsInput>,
): Promise<ParamsInput> {
  return Promise.resolve(params);
}

export const dynamic = "force-dynamic";

/**
 * Returns one trace with its ordered span timeline.
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

    const spanLimit = parsePositiveInt(url.searchParams.get("spanLimit"), 500, 2000);
    const projectScopeSql = scope.projectId
      ? Prisma.sql`AND ${buildProjectSqlCondition(Prisma.sql`"projectId"`, scope.projectId)}`
      : Prisma.empty;

    const [traces, spans] = await Promise.all([
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
        WHERE "traceId" = ${decodedTraceId}
        ${projectScopeSql}
        LIMIT 1
      `),
      prisma.$queryRaw<TraceSpanRecord[]>(Prisma.sql`
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
        ORDER BY s."ts" ASC, s."id" ASC
        LIMIT ${spanLimit}
      `),
    ]);

    const trace = traces[0];
    if (!trace) {
      return NextResponse.json({ error: "trace not found" }, { status: 404 });
    }

    return NextResponse.json({
      ok: true,
      trace: serializeTraceRecord(trace),
      spans: spans.map(serializeTraceSpanRecord),
    });
  } catch (err) {
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}
