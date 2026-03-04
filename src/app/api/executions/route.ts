/**
 * @fileoverview ClawSight SIEM module: platform/src/app/api/executions/route.ts.
 */
import { Prisma } from "@prisma/client";
import { NextRequest, NextResponse } from "next/server";
import { buildManagedAgentSqlCondition } from "@/lib/agents/filter";
import { prisma } from "@/lib/prisma";
import {
  deriveExecutionAgentKey,
  toExecution,
  type ExecutionRollupRow,
  type ExecutionTraceRow,
} from "@/lib/executions/mapper";
import type { Execution, ExecutionIntentSummary, ExecutionOutcome, TriggerType } from "@/lib/executions/types";

export const dynamic = "force-dynamic";

/**
 * Parses bounded positive integers from query params.
 */
function parsePositiveInt(value: string | null, fallback: number, max = 400): number {
  if (!value) return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) return fallback;
  return Math.min(parsed, max);
}

function normalize(value: string | null): string | undefined {
  const trimmed = String(value || "").trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

/**
 * Maps the `outcome` query param into canonical execution outcomes.
 */
function mapExecutionOutcome(input: string | null): ExecutionOutcome | undefined {
  const value = normalize(input)?.toLowerCase();
  if (!value) return undefined;
  if (value === "completed" || value === "error" || value === "blocked" || value === "running") {
    return value;
  }
  return undefined;
}

/**
 * Maps the `triggerType` query param into canonical trigger types.
 */
function mapTriggerType(input: string | null): TriggerType | undefined {
  const value = normalize(input)?.toLowerCase();
  if (!value) return undefined;
  if (
    value === "user" ||
    value === "cron" ||
    value === "webhook" ||
    value === "retry" ||
    value === "chain" ||
    value === "system"
  ) {
    return value;
  }
  return undefined;
}

/**
 * Returns execution rollups assembled from traces, telemetry, alerts, and intent state.
 */
export async function GET(request: NextRequest) {
  try {
    const url = new URL(request.url);
    const limit = parsePositiveInt(url.searchParams.get("limit"), 120, 250);
    const search = normalize(url.searchParams.get("search"));
    const agentKey = normalize(url.searchParams.get("agentKey"));
    const triggerType = mapTriggerType(url.searchParams.get("triggerType"));
    const outcome = mapExecutionOutcome(url.searchParams.get("outcome"));

    const conditions: Prisma.Sql[] = [];
    conditions.push(
      Prisma.sql`NOT (
        "traceId" LIKE 'agent:%:bootstrap'
        OR "traceId" LIKE 'session:%'
        OR (
          "traceId" ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
          AND COALESCE("rootExecutionId", '') = ''
          AND COALESCE("openclawRunId", '') = ''
          AND "endedAt" IS NULL
        )
      )`,
    );
    if (search) {
      const needle = `%${search}%`;
      conditions.push(
        Prisma.sql`(
          "traceId" ILIKE ${needle}
          OR COALESCE("openclawSessionKey", '') ILIKE ${needle}
          OR COALESCE("openclawAgentId", '') ILIKE ${needle}
          OR COALESCE("rootExecutionId", '') ILIKE ${needle}
        )`,
      );
    }
    if (agentKey) {
      const condition = buildManagedAgentSqlCondition({
        agentKey: decodeURIComponent(agentKey),
        projectColumn: Prisma.sql`"projectId"`,
        agentInstanceColumn: Prisma.sql`"agentInstanceId"`,
        sessionIdColumn: Prisma.sql`"openclawSessionId"`,
        openclawAgentColumn: Prisma.sql`"openclawAgentId"`,
        sessionKeyColumn: Prisma.sql`"openclawSessionKey"`,
      });
      if (condition) conditions.push(condition);
    }

    const whereClause =
      conditions.length > 0 ? Prisma.sql`WHERE ${Prisma.join(conditions, " AND ")}` : Prisma.empty;

    const traceRows = await prisma.$queryRaw<ExecutionTraceRow[]>(Prisma.sql`
      SELECT
        "traceId",
        "sourceType",
        "status",
        "startedAt",
        "endedAt",
        "durationMs",
        "errorCount",
        "blockCount",
        "openclawSessionKey",
        "openclawAgentId",
        "openclawSessionId",
        "agentInstanceId",
        "projectId",
        "rootExecutionId"
      FROM "Trace"
      ${whereClause}
      ORDER BY "lastEventTs" DESC
      LIMIT ${limit * 3}
    `);

    if (!traceRows.length) {
      return NextResponse.json({ ok: true, data: [] });
    }

    const traceIds = traceRows.map((row) => row.traceId);
    const traceIdSql = Prisma.join(traceIds.map((value) => Prisma.sql`${value}`));

    const rootKeys = Array.from(new Set(traceRows.map((row) => row.rootExecutionId || row.traceId)));
    const rootKeysSql = Prisma.join(rootKeys.map((value) => Prisma.sql`${value}`));

    const [eventRollups, domainRollups, alertRollups, agents, intentRows, intentDecisionRows] = await Promise.all([
      prisma.$queryRaw<
        Array<{ traceId: string; toolCalls: number; errors: number; channelsInvolved: string[] | null }>
      >(Prisma.sql`
        SELECT
          "traceId",
          COUNT(*) FILTER (WHERE category = 'tool' AND action = 'before_tool_call')::int AS "toolCalls",
          COUNT(*) FILTER (WHERE severity = 'error' OR outcome = 'error')::int AS "errors",
          array_remove(
            array_agg(
              DISTINCT NULLIF(
                COALESCE(
                  payload #>> '{execution,messageProvider}',
                  payload #>> '{channelId}',
                  payload #>> '{channel}',
                  payload #>> '{provider}'
                ),
                ''
              )
            ),
            NULL
          ) AS "channelsInvolved"
        FROM "TelemetryEvent"
        WHERE "traceId" IN (${traceIdSql})
        GROUP BY "traceId"
      `),
      prisma.$queryRaw<Array<{ traceId: string; domainsTouched: number }>>(Prisma.sql`
        SELECT
          e."traceId" AS "traceId",
          COUNT(DISTINCT o.value)::int AS "domainsTouched"
        FROM "TelemetryObservable" o
        JOIN "TelemetryEvent" e ON e.id = o."eventId"
        WHERE o.kind = 'domain'
          AND e."category" = 'tool'
          AND e."traceId" IN (${traceIdSql})
        GROUP BY e."traceId"
      `),
      prisma.$queryRaw<Array<{ traceId: string; alertsRaised: number }>>(Prisma.sql`
        SELECT
          COALESCE(a."executionId", e."traceId") AS "traceId",
          COUNT(*)::int AS "alertsRaised"
        FROM "ThreatAlert" a
        LEFT JOIN "TelemetryEvent" e ON e."eventId" = a."eventId"
        WHERE COALESCE(a."executionId", e."traceId") IN (${traceIdSql})
          AND a."alertModel" = 'execution_v2'
        GROUP BY COALESCE(a."executionId", e."traceId")
      `),
      prisma.managedAgent.findMany({
        select: {
          agentKey: true,
          displayName: true,
          reportedName: true,
          agentInstanceId: true,
        },
        take: 500,
      }),
      prisma.$queryRaw<
        Array<{
          rootExecutionId: string;
          driftScore: number;
          status: string;
          taskBoundary: string | null;
          expectedScopes: unknown;
          expectedDomains: unknown;
        }>
      >(Prisma.sql`
        SELECT DISTINCT ON ("rootExecutionId")
          "rootExecutionId",
          "driftScore",
          "status",
          "taskBoundary",
          "expectedScopes",
          "expectedDomains"
        FROM "ExecutionIntent"
        WHERE "rootExecutionId" IN (${rootKeysSql})
        ORDER BY "rootExecutionId", "updatedAt" DESC
      `),
      prisma.$queryRaw<
        Array<{
          rootExecutionId: string;
          decisionsCount: number;
          warnsCount: number;
          blocksCount: number;
          sanitizedCount: number;
        }>
      >(Prisma.sql`
        SELECT
          "rootExecutionId",
          COUNT(*)::int AS "decisionsCount",
          COUNT(*) FILTER (WHERE action = 'warn')::int AS "warnsCount",
          COUNT(*) FILTER (WHERE action = 'block')::int AS "blocksCount",
          COUNT(*) FILTER (WHERE phase = 'tool_output' AND action = 'modify')::int AS "sanitizedCount"
        FROM "IntentDecision"
        WHERE "rootExecutionId" IN (${rootKeysSql})
        GROUP BY "rootExecutionId"
      `),
    ]);

    const rollupMap = new Map<string, ExecutionRollupRow>();
    for (const row of eventRollups) {
      rollupMap.set(row.traceId, {
        traceId: row.traceId,
        toolCalls: row.toolCalls ?? 0,
        errors: row.errors ?? 0,
        domainsTouched: 0,
        alertsRaised: 0,
        channelsInvolved: (row.channelsInvolved || []).filter(Boolean),
      });
    }
    for (const row of domainRollups) {
      const current = rollupMap.get(row.traceId);
      if (current) {
        current.domainsTouched = row.domainsTouched ?? 0;
      } else {
        rollupMap.set(row.traceId, {
          traceId: row.traceId,
          toolCalls: 0,
          errors: 0,
          domainsTouched: row.domainsTouched ?? 0,
          alertsRaised: 0,
          channelsInvolved: [],
        });
      }
    }
    for (const row of alertRollups) {
      const current = rollupMap.get(row.traceId);
      if (current) {
        current.alertsRaised = row.alertsRaised ?? 0;
      } else {
        rollupMap.set(row.traceId, {
          traceId: row.traceId,
          toolCalls: 0,
          errors: 0,
          domainsTouched: 0,
          alertsRaised: row.alertsRaised ?? 0,
          channelsInvolved: [],
        });
      }
    }

    const agentNameByKey = new Map(
      agents.map((agent) => [
        agent.agentKey,
        agent.displayName || agent.reportedName || agent.agentInstanceId || agent.agentKey,
      ]),
    );

    const intentDecisionMap = new Map(
      intentDecisionRows.map((row) => [row.rootExecutionId, row]),
    );

    function deriveDriftStatus(
      driftScore: number,
      blockCount: number,
    ): ExecutionIntentSummary["driftStatus"] {
      if (blockCount > 0 || driftScore >= 70) return "blocked";
      if (driftScore >= 55) return "high";
      if (driftScore >= 30) return "elevated";
      return "normal";
    }

    const intentSummaryByRoot = new Map<string, ExecutionIntentSummary>();
    for (const row of intentRows) {
      const decision = intentDecisionMap.get(row.rootExecutionId);
      const decisionsCount = decision?.decisionsCount || 0;
      const warnsCount = decision?.warnsCount || 0;
      const blocksCount = decision?.blocksCount || 0;
      const sanitizedCount = decision?.sanitizedCount || 0;
      const baselineExtracted = Boolean(
        row.taskBoundary ||
        (Array.isArray(row.expectedScopes) && row.expectedScopes.length > 0) ||
        (Array.isArray(row.expectedDomains) && row.expectedDomains.length > 0),
      );
      intentSummaryByRoot.set(row.rootExecutionId, {
        baselineExtracted,
        currentDriftScore: row.driftScore || 0,
        driftStatus: deriveDriftStatus(row.driftScore || 0, blocksCount),
        decisionsCount,
        warnsCount,
        blocksCount,
        sanitizedCount,
      });
    }

    const executions: Execution[] = traceRows
      .map((row) => {
        const agentKeyDerived = deriveExecutionAgentKey(row);
        const fallbackName =
          row.openclawAgentId || row.agentInstanceId || row.openclawSessionKey || "unknown-agent";
        const rootKey = row.rootExecutionId || row.traceId;
        return toExecution(
          row,
          rollupMap.get(row.traceId),
          agentNameByKey.get(agentKeyDerived) || fallbackName,
          intentSummaryByRoot.get(rootKey),
        );
      })
      .filter((row) => (triggerType ? row.triggerType === triggerType : true))
      .filter((row) => (outcome ? row.outcome === outcome : true))
      .slice(0, limit);

    return NextResponse.json({ ok: true, data: executions });
  } catch (error) {
    return NextResponse.json({ ok: false, error: String(error) }, { status: 500 });
  }
}
