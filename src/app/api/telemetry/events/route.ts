/**
 * @fileoverview ClawSight SIEM module: platform/src/app/api/telemetry/events/route.ts.
 */
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import {
  buildTelemetryEventWhere,
  parseTelemetryEventFiltersFromUrl,
  serializeTelemetryEvent,
} from "@/lib/telemetry-event-query";

export async function GET(request: NextRequest) {
  try {
    const url = new URL(request.url);
    const filters = parseTelemetryEventFiltersFromUrl(url);
    const where = buildTelemetryEventWhere(filters);

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
