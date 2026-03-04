/**
 * @fileoverview ClawSight SIEM module: platform/src/app/api/telemetry/events/stream/route.ts.
 */
import { Prisma } from "@prisma/client";
import { NextRequest } from "next/server";
import { authorizeReadRequest, buildProjectWhere, resolveProjectScope } from "@/lib/auth";
import { prisma } from "@/lib/prisma";
import {
  buildTelemetryEventWhere,
  parseTelemetryEventFiltersFromUrl,
  serializeTelemetryEvent,
} from "@/lib/telemetry-event-query";

const POLL_MS = 1200;
const POLL_BATCH = 120;
const HEARTBEAT_MS = 15000;

export const dynamic = "force-dynamic";

function parseUnsignedInt(value: string | null): number | undefined {
  if (!value) return undefined;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) return undefined;
  return parsed;
}

function parseFiltersFromRequest(request: NextRequest) {
  const url = new URL(request.url);
  const filters = parseTelemetryEventFiltersFromUrl(url);
  const cursorTs = parseUnsignedInt(url.searchParams.get("cursorTs"));
  const cursorId = parseUnsignedInt(url.searchParams.get("cursorId"));
  const hasCursor = cursorTs !== undefined || cursorId !== undefined;
  return { filters, cursorTs: hasCursor ? cursorTs : Date.now(), cursorId };
}

function buildDeltaWhere(where: Prisma.TelemetryEventWhereInput, cursorTs?: number, cursorId?: number) {
  if (cursorTs === undefined && cursorId === undefined) {
    return where;
  }
  if (cursorTs === undefined && cursorId !== undefined) {
    return { ...where, id: { gt: cursorId } };
  }
  if (cursorTs === undefined) {
    return where;
  }

  const cursorDate = new Date(cursorTs);
  if (cursorId === undefined) {
    return { ...where, ts: { gt: cursorDate } };
  }
  return {
    ...where,
    OR: [
      { ts: { gt: cursorDate } },
      { AND: [{ ts: { equals: cursorDate } }, { id: { gt: cursorId } }] },
    ],
  };
}

function encodeEvent(name: string, data: unknown) {
  return `event: ${name}\ndata: ${JSON.stringify(data)}\n\n`;
}

/**
 * Streams telemetry events over SSE using cursor-based polling.
 */
export async function GET(request: NextRequest) {
  const unauthorized = authorizeReadRequest(request);
  if (unauthorized) return unauthorized;

  const { filters, cursorTs, cursorId } = parseFiltersFromRequest(request);
  const scope = resolveProjectScope(request, filters.projectId);
  if (scope.response) return scope.response;
  filters.projectId = scope.projectId;
  const where = buildTelemetryEventWhere(filters);
  if (scope.projectId) {
    const andClauses = Array.isArray(where.AND)
      ? where.AND
      : where.AND
        ? [where.AND]
        : [];
    where.AND = [...andClauses, buildProjectWhere(scope.projectId)];
  }
  const encoder = new TextEncoder();
  const pollTake = Math.min(filters.limit, POLL_BATCH);
  const pollInterval = POLL_MS;

  const stream = new ReadableStream({
    start(controller) {
      let closed = false;
      let lastCursorTs: number | undefined = cursorTs;
      let lastCursorId: number | undefined = cursorId;
      let polling = false;

      const send = (chunk: string) => controller.enqueue(encoder.encode(chunk));
      const close = () => {
        if (closed) return;
        closed = true;
        clearInterval(pollTimer);
        clearInterval(heartbeatTimer);
        controller.close();
      };

      const poll = async () => {
        if (polling || closed) {
          return;
        }
        polling = true;
        try {
          const deltaWhere = buildDeltaWhere(where, lastCursorTs, lastCursorId);
          const rows = await prisma.telemetryEvent.findMany({
            where: deltaWhere,
            orderBy: [{ ts: "asc" }, { id: "asc" }],
            take: pollTake,
          });
          if (!rows.length) {
            return;
          }
          for (const row of rows) {
            const event = serializeTelemetryEvent(row);
            lastCursorTs = event.ts;
            lastCursorId = event.id;
            send(encodeEvent("telemetry", event));
          }
        } catch (err) {
          if (closed) {
            return;
          }
          send(encodeEvent("stream-error", { message: String(err) }));
        } finally {
          polling = false;
        }
      };

      const pollTimer = setInterval(() => {
        void poll();
      }, pollInterval);
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
