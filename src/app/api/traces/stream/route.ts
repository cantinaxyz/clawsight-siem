/**
 * @fileoverview ClawSight SIEM module: platform/src/app/api/traces/stream/route.ts.
 */
import { Prisma } from "@prisma/client";
import { NextRequest } from "next/server";
import { buildManagedAgentSqlCondition } from "@/lib/agents/filter";
import { authorizeReadRequest, buildProjectSqlCondition, resolveProjectScope } from "@/lib/auth";
import { prisma } from "@/lib/prisma";
import {
  parseTraceFiltersFromUrl,
  serializeTraceRecord,
  type TraceRecord,
} from "@/lib/traces/query";

const POLL_MS = 1200;
const POLL_BATCH = 80;
const HEARTBEAT_MS = 15000;

export const dynamic = "force-dynamic";

function parseUnsignedInt(value: string | null): number | undefined {
  if (!value) return undefined;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) return undefined;
  return parsed;
}

function parseRequest(request: NextRequest) {
  const url = new URL(request.url);
  const filters = parseTraceFiltersFromUrl(url);
  const requestedProjectId = url.searchParams.get("projectId")?.trim() || undefined;
  const cursorTs = parseUnsignedInt(url.searchParams.get("cursorTs"));
  const cursorTraceId = url.searchParams.get("cursorTraceId")?.trim() || undefined;
  const hasCursor = cursorTs !== undefined || cursorTraceId !== undefined;
  return {
    filters,
    requestedProjectId,
    cursorTs: hasCursor ? cursorTs : Date.now(),
    cursorTraceId,
  };
}

function encodeEvent(name: string, data: unknown) {
  return `event: ${name}\ndata: ${JSON.stringify(data)}\n\n`;
}

function buildFilterSql(
  filters: ReturnType<typeof parseTraceFiltersFromUrl>,
  projectId?: string,
): Prisma.Sql {
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
  if (projectId) {
    conditions.push(buildProjectSqlCondition(Prisma.sql`"projectId"`, projectId));
  }
  if (conditions.length === 0) return Prisma.empty;
  return Prisma.sql`AND ${Prisma.join(conditions, " AND ")}`;
}

/**
 * Streams trace deltas over SSE using `updatedAt + traceId` cursor ordering.
 */
export async function GET(request: NextRequest) {
  const unauthorized = authorizeReadRequest(request);
  if (unauthorized) return unauthorized;

  const { filters, requestedProjectId, cursorTs, cursorTraceId } = parseRequest(request);
  const scope = resolveProjectScope(request, requestedProjectId);
  if (scope.response) return scope.response;
  const encoder = new TextEncoder();
  const pollTake = Math.min(filters.limit, POLL_BATCH);
  const filterSql = buildFilterSql(filters, scope.projectId);

  const stream = new ReadableStream({
    start(controller) {
      let closed = false;
      let polling = false;
      let lastCursorTs: number | undefined = cursorTs;
      let lastCursorTraceId: string | undefined = cursorTraceId;

      const send = (chunk: string) => controller.enqueue(encoder.encode(chunk));
      const close = () => {
        if (closed) return;
        closed = true;
        clearInterval(pollTimer);
        clearInterval(heartbeatTimer);
        controller.close();
      };

      const poll = async () => {
        if (closed || polling) return;
        polling = true;
        try {
          const cursorDate = new Date(lastCursorTs ?? Date.now());
          const cursorClause =
            lastCursorTraceId != null
              ? Prisma.sql`(
                  "updatedAt" > ${cursorDate}
                  OR ("updatedAt" = ${cursorDate} AND "traceId" > ${lastCursorTraceId})
                )`
              : Prisma.sql`"updatedAt" > ${cursorDate}`;

          const rows = await prisma.$queryRaw<TraceRecord[]>(Prisma.sql`
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
            WHERE ${cursorClause}
            ${filterSql}
            ORDER BY "updatedAt" ASC, "traceId" ASC
            LIMIT ${pollTake}
          `);
          if (!rows.length) return;

          for (const row of rows) {
            const serialized = serializeTraceRecord(row);
            lastCursorTs = serialized.updatedAt;
            lastCursorTraceId = serialized.traceId;
            send(encodeEvent("trace", serialized));
          }
        } catch (err) {
          if (closed) return;
          send(encodeEvent("stream-error", { message: String(err) }));
        } finally {
          polling = false;
        }
      };

      const pollTimer = setInterval(() => {
        void poll();
      }, POLL_MS);
      const heartbeatTimer = setInterval(() => {
        if (closed) return;
        send(": heartbeat\n\n");
      }, HEARTBEAT_MS);

      void poll();
      request.signal.addEventListener(
        "abort",
        () => {
          close();
        },
        { once: true },
      );
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-store, must-revalidate",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}
