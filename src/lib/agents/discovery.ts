/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/agents/discovery.ts.
 */
import { prisma } from "@/lib/prisma";
import { upsertDiscoveredAgents } from "@/lib/agents/repository";

const DEFAULT_LIMIT = 400;

/**
 * Discovers agent identities from recent telemetry events.
 *
 * @param limit Upper bound for source rows scanned.
 * @returns Number of discovery records processed by repository upsert.
 */
export async function discoverFromTelemetry(limit = DEFAULT_LIMIT) {
  const rows = await prisma.telemetryEvent.findMany({
    where: {
      OR: [
        { agentInstanceId: { not: null } },
        { openclawAgentId: { not: null } },
        { openclawSessionId: { not: null } },
        { openclawSessionKey: { not: null } },
      ],
    },
    select: {
      projectId: true,
      agentInstanceId: true,
      agentName: true,
      openclawAgentId: true,
      openclawSessionId: true,
      openclawSessionKey: true,
      ts: true,
    },
    orderBy: { ts: "desc" },
    take: Math.min(Math.max(limit, 10), 2000),
  });

  return upsertDiscoveredAgents(
    rows.map((row) => ({
      projectId: row.projectId,
      agentInstanceId: row.agentInstanceId,
      agentName: row.agentName,
      openclawAgentId: row.openclawAgentId,
      openclawSessionId: row.openclawSessionId,
      openclawSessionKey: row.openclawSessionKey,
      seenAt: row.ts,
    })),
  );
}

/**
 * Discovers agent identities from trace rows when event metadata is sparse.
 *
 * @param limit Upper bound for source rows scanned.
 * @returns Number of discovery records processed by repository upsert.
 */
export async function discoverFromTraces(limit = DEFAULT_LIMIT) {
  const rows = await prisma.trace.findMany({
    where: {
      OR: [
        { agentInstanceId: { not: null } },
        { openclawAgentId: { not: null } },
        { openclawSessionId: { not: null } },
        { openclawSessionKey: { not: null } },
      ],
    },
    select: {
      projectId: true,
      agentInstanceId: true,
      openclawAgentId: true,
      openclawSessionId: true,
      openclawSessionKey: true,
      lastEventTs: true,
    },
    orderBy: { lastEventTs: "desc" },
    take: Math.min(Math.max(limit, 10), 2000),
  });

  return upsertDiscoveredAgents(
    rows.map((row) => ({
      projectId: row.projectId,
      agentInstanceId: row.agentInstanceId,
      openclawAgentId: row.openclawAgentId,
      openclawSessionId: row.openclawSessionId,
      openclawSessionKey: row.openclawSessionKey,
      seenAt: row.lastEventTs,
    })),
  );
}

/**
 * Runs both discovery strategies and returns total processed rows.
 */
export async function discoverManagedAgents(limit = DEFAULT_LIMIT) {
  const [fromEvents, fromTraces] = await Promise.all([
    discoverFromTelemetry(limit),
    discoverFromTraces(limit),
  ]);
  return fromEvents + fromTraces;
}
