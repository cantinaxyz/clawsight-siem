/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/telemetry-event-query.ts.
 */
import type { Prisma, TelemetryEvent } from "@prisma/client";
import { buildManagedAgentEventWhere } from "@/lib/agents/filter";

export type TelemetryEventFilterInput = {
  category?: string;
  outcome?: string;
  policyRuleId?: string;
  projectId?: string;
  agentKey?: string;
  requestId?: string;
  sessionKey?: string;
  sessionId?: string;
  search?: string;
  limit: number;
};

export type SerializedTelemetryEvent = Omit<TelemetryEvent, "ts"> & {
  ts: number;
};

/**
 * Parses bounded positive integers from query params.
 */
export function parsePositiveInt(
  value: string | null,
  fallback: number,
  max = 500,
): number {
  if (!value) return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) return fallback;
  return Math.min(parsed, max);
}

/**
 * Extracts telemetry-event list filters from URL query params.
 */
export function parseTelemetryEventFiltersFromUrl(url: URL): TelemetryEventFilterInput {
  const q = url.searchParams;
  const search = q.get("search")?.trim() || q.get("q")?.trim() || undefined;

  return {
    category: q.get("category")?.trim() || undefined,
    outcome: q.get("outcome")?.trim() || undefined,
    policyRuleId: q.get("policyRuleId")?.trim() || undefined,
    projectId: q.get("projectId")?.trim() || undefined,
    agentKey: q.get("agentKey")?.trim() || undefined,
    requestId: q.get("requestId")?.trim() || undefined,
    sessionKey: q.get("sessionKey")?.trim() || undefined,
    sessionId: q.get("sessionId")?.trim() || undefined,
    search: search && search.length > 0 ? search : undefined,
    limit: parsePositiveInt(q.get("limit"), 200),
  };
}

/**
 * Builds Prisma `where` conditions for telemetry-event filtering.
 */
export function buildTelemetryEventWhere(filters: TelemetryEventFilterInput): Prisma.TelemetryEventWhereInput {
  const where: Prisma.TelemetryEventWhereInput = {};
  const andClauses: Prisma.TelemetryEventWhereInput[] = [];

  if (filters.category) {
    where.category = filters.category;
  }
  if (filters.outcome) {
    where.outcome = filters.outcome;
  }
  if (filters.policyRuleId) {
    where.policyRuleId = filters.policyRuleId;
  }
  if (filters.projectId) {
    where.projectId = filters.projectId;
  }
  if (filters.agentKey) {
    const agentWhere = buildManagedAgentEventWhere(filters.agentKey);
    if (agentWhere) {
      andClauses.push(agentWhere);
    }
  }
  if (filters.requestId) {
    where.requestId = filters.requestId;
  }
  if (filters.sessionKey) {
    where.openclawSessionKey = filters.sessionKey;
  }
  if (filters.sessionId) {
    where.openclawSessionId = filters.sessionId;
  }

  if (filters.search) {
    const needle = filters.search.toLowerCase();
    andClauses.push({
      OR: [
      { action: { contains: needle, mode: "insensitive" } },
      { category: { contains: needle, mode: "insensitive" } },
      { severity: { contains: needle, mode: "insensitive" } },
      { outcome: { contains: needle, mode: "insensitive" } },
      { outcomeReason: { contains: needle, mode: "insensitive" } },
      { policyRuleId: { contains: needle, mode: "insensitive" } },
      { openclawToolName: { contains: needle, mode: "insensitive" } },
      { iocValue: { contains: needle, mode: "insensitive" } },
      { requestId: { contains: needle, mode: "insensitive" } },
      { agentName: { contains: needle, mode: "insensitive" } },
      ],
    });
  }

  if (andClauses.length > 0) {
    where.AND = andClauses;
  }

  return where;
}

/**
 * Serializes event timestamps to epoch milliseconds for client transport.
 */
export function serializeTelemetryEvent(event: TelemetryEvent): SerializedTelemetryEvent {
  return {
    ...event,
    ts: event.ts.getTime(),
  };
}
