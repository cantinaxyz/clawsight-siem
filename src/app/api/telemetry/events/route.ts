/**
 * @fileoverview ClawSight SIEM module: platform/src/app/api/telemetry/events/route.ts.
 */
import { NextRequest, NextResponse } from "next/server";
import { authorizeReadRequest, buildProjectWhere, resolveProjectScope } from "@/lib/auth";
import { prisma } from "@/lib/prisma";
import {
  buildTelemetryEventWhere,
  parseTelemetryEventFiltersFromUrl,
  serializeTelemetryEvent,
} from "@/lib/telemetry-event-query";

export async function GET(request: NextRequest) {
  try {
    const unauthorized = authorizeReadRequest(request);
    if (unauthorized) return unauthorized;

    const url = new URL(request.url);
    const filters = parseTelemetryEventFiltersFromUrl(url);
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

    const [events, total] = await Promise.all([
      prisma.telemetryEvent.findMany({
        where,
        orderBy: [{ ts: "desc" }],
        take: filters.limit,
      }),
      prisma.telemetryEvent.count({ where }),
    ]);

    return NextResponse.json({
      ok: true,
      total,
      data: events.map(serializeTelemetryEvent),
    });
  } catch (err) {
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}
