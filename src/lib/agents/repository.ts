/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/agents/repository.ts.
 */
import { Prisma } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import {
  deriveManagedAgentKey,
  deriveManagedAgentLabel,
  parseManagedAgentKey,
  type AgentIdentityInput,
} from "@/lib/agents/identity";

export type ManagedAgentFilters = {
  projectId?: string;
  search?: string;
  limit?: number;
};

export type DiscoverAgentInput = AgentIdentityInput & {
  seenAt: Date;
  sourceType?: "discovered" | "bootstrap";
  reportedName?: string | null;
  runtimeMeta?: Prisma.InputJsonValue | null;
  bootstrapAt?: Date | null;
};

/**
 * Upserts discovered agent identities and keeps first/last seen timestamps monotonic.
 *
 * @param inputs Raw discovery signals from telemetry/trace pipelines.
 * @returns Number of normalized input records processed.
 */
export async function upsertDiscoveredAgents(inputs: DiscoverAgentInput[]): Promise<number> {
  if (inputs.length === 0) return 0;

  const normalized = inputs
    .map((item) => {
      const key = deriveManagedAgentKey(item);
      const label = deriveManagedAgentLabel(item);
      return {
        key,
        label,
        seenAt: item.seenAt,
        sourceType: item.sourceType === "bootstrap" ? "bootstrap" : "discovered",
        reportedName: item.reportedName?.trim() || item.agentName?.trim() || null,
        runtimeMeta: item.runtimeMeta ?? null,
        bootstrapAt: item.bootstrapAt ?? null,
        projectId: item.projectId?.trim() || null,
        agentInstanceId: item.agentInstanceId?.trim() || null,
        openclawSessionId: item.openclawSessionId?.trim() || null,
        openclawAgentId: item.openclawAgentId?.trim() || null,
      };
    })
    .sort((a, b) => a.seenAt.getTime() - b.seenAt.getTime());

  for (const item of normalized) {
    await prisma.managedAgent.upsert({
      where: { agentKey: item.key },
      create: {
        agentKey: item.key,
        displayName: item.label,
        reportedName: item.reportedName,
        projectId: item.projectId,
        agentInstanceId: item.agentInstanceId,
        openclawSessionId: item.openclawSessionId,
        openclawAgentId: item.openclawAgentId,
        runtimeMeta: item.runtimeMeta ?? Prisma.JsonNull,
        sourceType: item.sourceType,
        policyProfile: "inherit_global",
        firstSeenAt: item.seenAt,
        lastSeenAt: item.seenAt,
        lastBootstrapAt: item.bootstrapAt,
      },
      update: {
        projectId: item.projectId || undefined,
        agentInstanceId: item.agentInstanceId || undefined,
        openclawSessionId: item.openclawSessionId || undefined,
        openclawAgentId: item.openclawAgentId || undefined,
        reportedName: item.reportedName || undefined,
        runtimeMeta: item.runtimeMeta || undefined,
        sourceType: item.sourceType === "bootstrap" ? "bootstrap" : undefined,
        lastBootstrapAt: item.bootstrapAt || undefined,
      },
    });

    await prisma.$executeRaw(Prisma.sql`
      UPDATE "ManagedAgent"
      SET
        "firstSeenAt" = LEAST("firstSeenAt", ${item.seenAt}),
        "lastSeenAt" = GREATEST("lastSeenAt", ${item.seenAt}),
        "updatedAt" = NOW()
      WHERE "agentKey" = ${item.key}
    `);
  }

  return normalized.length;
}

/**
 * Lists managed agents with optional project/search filtering.
 *
 * @param filters Query constraints for project, fuzzy search, and bounded limit.
 * @returns Ordered managed-agent records (newest activity first).
 */
export async function listManagedAgents(filters: ManagedAgentFilters = {}) {
  const where: Prisma.ManagedAgentWhereInput = {};

  if (filters.projectId) {
    where.projectId = filters.projectId;
  }
  if (filters.search) {
    const needle = filters.search.trim();
    where.OR = [
      { agentKey: { contains: needle, mode: "insensitive" } },
      { displayName: { contains: needle, mode: "insensitive" } },
      { reportedName: { contains: needle, mode: "insensitive" } },
      { openclawAgentId: { contains: needle, mode: "insensitive" } },
      { openclawSessionId: { contains: needle, mode: "insensitive" } },
      { agentInstanceId: { contains: needle, mode: "insensitive" } },
      { projectId: { contains: needle, mode: "insensitive" } },
    ];
  }

  return prisma.managedAgent.findMany({
    where,
    orderBy: [{ lastSeenAt: "desc" }, { id: "desc" }],
    take: Math.min(Math.max(filters.limit || 100, 1), 300),
  });
}

/**
 * Fetches a single managed agent by durable agent key.
 *
 * @param agentKey Canonical `inst:/sid:/oc:/sess:` key.
 * @returns Managed agent record or null when not found.
 */
export async function getManagedAgent(agentKey: string) {
  return prisma.managedAgent.findUnique({ where: { agentKey } });
}

/**
 * Applies editable profile fields for an existing managed agent.
 *
 * @param input Partial profile payload from UI/API.
 * @returns Updated managed-agent record.
 */
export async function updateManagedAgent(input: {
  agentKey: string;
  displayName?: string | null;
  notes?: string | null;
  policyProfile?: string | null;
}) {
  return prisma.managedAgent.update({
    where: { agentKey: input.agentKey },
    data: {
      displayName: input.displayName?.trim() || undefined,
      notes: input.notes?.trim() || undefined,
      policyProfile: input.policyProfile === "custom" ? "custom" : input.policyProfile === "inherit_global" ? "inherit_global" : undefined,
    },
  });
}

/**
 * Normalizes nullable string arrays to unique, non-empty values.
 */
function nonEmpty(values: Array<string | null | undefined>): string[] {
  return Array.from(
    new Set(
      values
        .map((value) => String(value || "").trim())
        .filter((value) => value.length > 0),
    ),
  );
}

/**
 * Builds SQL project scoping that treats null/empty as `default`.
 */
function projectScopeSql(projectColumn: Prisma.Sql, projectId: string): Prisma.Sql {
  if (projectId === "default") {
    return Prisma.sql`COALESCE(NULLIF(${projectColumn}, ''), 'default') = 'default'`;
  }
  return Prisma.sql`COALESCE(NULLIF(${projectColumn}, ''), 'default') = ${projectId}`;
}

/**
 * Builds a SQL predicate for matching agent-scoped identities across heterogeneous tables.
 *
 * The resulting predicate is used for hard-delete cleanup where each table can expose a
 * different subset of identity columns.
 */
function buildScopedSqlCondition(input: {
  projectId: string;
  agentInstanceIds: string[];
  openclawAgentIds: string[];
  openclawSessionIds: string[];
  openclawSessionKeys: string[];
  projectColumn: Prisma.Sql;
  agentInstanceColumn?: Prisma.Sql;
  openclawAgentColumn?: Prisma.Sql;
  openclawSessionIdColumn?: Prisma.Sql;
  openclawSessionKeyColumn?: Prisma.Sql;
}): Prisma.Sql | null {
  const identityPredicates: Prisma.Sql[] = [];

  if (input.agentInstanceColumn) {
    for (const value of input.agentInstanceIds) {
      identityPredicates.push(Prisma.sql`${input.agentInstanceColumn} = ${value}`);
    }
  }
  if (input.openclawAgentColumn) {
    for (const value of input.openclawAgentIds) {
      identityPredicates.push(Prisma.sql`${input.openclawAgentColumn} = ${value}`);
    }
  }
  if (input.openclawSessionIdColumn) {
    for (const value of input.openclawSessionIds) {
      identityPredicates.push(Prisma.sql`${input.openclawSessionIdColumn} = ${value}`);
    }
  }
  if (input.openclawSessionKeyColumn) {
    for (const value of input.openclawSessionKeys) {
      identityPredicates.push(Prisma.sql`${input.openclawSessionKeyColumn} = ${value}`);
    }
  }

  if (identityPredicates.length === 0) return null;
  return Prisma.sql`(${projectScopeSql(input.projectColumn, input.projectId)} AND (${Prisma.join(identityPredicates, " OR ")}))`;
}

/**
 * Permanently deletes a managed agent and all agent-scoped artifacts.
 *
 * This is the destructive cleanup entrypoint used by Agent Settings. It removes:
 * - registry/profile rows
 * - agent-scoped policy + intent config
 * - telemetry events/traces/spans (via trace cascade)
 * - execution intent/decisions/risk rollups
 * - alert rows and trace-orphan rows tied to the identity scope
 *
 * @param agentKey Canonical managed-agent key.
 */
export async function deleteManagedAgentAndData(agentKey: string): Promise<void> {
  const normalizedKey = String(agentKey || "").trim();
  if (!normalizedKey) return;

  const managedAgent = await prisma.managedAgent.findUnique({
    where: { agentKey: normalizedKey },
  });
  if (!managedAgent) return;

  const parsed = parseManagedAgentKey(normalizedKey);
  const projectId = parsed?.projectId || String(managedAgent.projectId || "").trim() || "default";
  const scopedInstanceId = parsed?.kind === "inst" ? parsed.value : null;
  const scopedOpenclawAgentId = parsed?.kind === "oc" ? parsed.value : null;
  const scopedSessionId = parsed?.kind === "sid" ? parsed.value : null;
  const scopedSessionKey = parsed?.kind === "sess" ? parsed.value : null;

  const identity = {
    projectId,
    agentInstanceIds: nonEmpty([managedAgent.agentInstanceId, scopedInstanceId]),
    openclawAgentIds: nonEmpty([managedAgent.openclawAgentId, scopedOpenclawAgentId]),
    openclawSessionIds: nonEmpty([managedAgent.openclawSessionId, scopedSessionId]),
    openclawSessionKeys: nonEmpty([scopedSessionKey]),
  };

  await prisma.$transaction(async (tx) => {
    const traceCondition = buildScopedSqlCondition({
      ...identity,
      projectColumn: Prisma.sql`"projectId"`,
      agentInstanceColumn: Prisma.sql`"agentInstanceId"`,
      openclawAgentColumn: Prisma.sql`"openclawAgentId"`,
      openclawSessionIdColumn: Prisma.sql`"openclawSessionId"`,
      openclawSessionKeyColumn: Prisma.sql`"openclawSessionKey"`,
    });

    const traceRows = traceCondition
      ? await tx.$queryRaw<Array<{ traceId: string; rootExecutionId: string | null }>>(Prisma.sql`
          SELECT "traceId", "rootExecutionId"
          FROM "Trace"
          WHERE ${traceCondition}
        `)
      : [];

    const traceIds = nonEmpty(traceRows.map((row) => row.traceId));
    const rootExecutionIds = nonEmpty(traceRows.map((row) => row.rootExecutionId));

    const executionIntentWhere: Prisma.ExecutionIntentWhereInput = {
      OR: [
        { managedAgentKey: normalizedKey },
        identity.agentInstanceIds.length > 0 ? { agentInstanceId: { in: identity.agentInstanceIds } } : undefined,
        rootExecutionIds.length > 0 ? { rootExecutionId: { in: rootExecutionIds } } : undefined,
      ].filter(Boolean) as Prisma.ExecutionIntentWhereInput[],
    };

    const executionIntents = await tx.executionIntent.findMany({
      where: executionIntentWhere,
      select: { executionKey: true, rootExecutionId: true },
    });

    const executionKeys = nonEmpty(executionIntents.map((row) => row.executionKey));
    for (const value of executionIntents.map((row) => row.rootExecutionId)) {
      if (value && !rootExecutionIds.includes(value)) rootExecutionIds.push(value);
    }

    if (traceIds.length > 0 || rootExecutionIds.length > 0 || identity.agentInstanceIds.length > 0) {
      const alertPredicates: Prisma.Sql[] = [];
      const alertCondition = buildScopedSqlCondition({
        ...identity,
        projectColumn: Prisma.sql`"projectId"`,
        agentInstanceColumn: Prisma.sql`"agentInstanceId"`,
        openclawAgentColumn: Prisma.sql`"openclawAgentId"`,
        openclawSessionKeyColumn: Prisma.sql`"openclawSessionKey"`,
      });
      if (alertCondition) alertPredicates.push(alertCondition);
      if (traceIds.length > 0) {
        const traceIdSql = Prisma.join(traceIds.map((value) => Prisma.sql`${value}`));
        alertPredicates.push(Prisma.sql`"executionId" IN (${traceIdSql})`);
      }
      if (rootExecutionIds.length > 0) {
        const rootExecutionSql = Prisma.join(rootExecutionIds.map((value) => Prisma.sql`${value}`));
        alertPredicates.push(Prisma.sql`"rootExecutionId" IN (${rootExecutionSql})`);
      }
      if (alertPredicates.length > 0) {
        await tx.$executeRaw(Prisma.sql`
          DELETE FROM "ThreatAlert"
          WHERE ${Prisma.join(alertPredicates, " OR ")}
        `);
      }
    }

    if (traceIds.length > 0 || rootExecutionIds.length > 0 || identity.agentInstanceIds.length > 0 || identity.openclawAgentIds.length > 0) {
      const riskPredicates: Prisma.Sql[] = [];
      const riskCondition = buildScopedSqlCondition({
        ...identity,
        projectColumn: Prisma.sql`"projectId"`,
        agentInstanceColumn: Prisma.sql`"agentInstanceId"`,
        openclawAgentColumn: Prisma.sql`"openclawAgentId"`,
      });
      if (riskCondition) riskPredicates.push(riskCondition);
      if (traceIds.length > 0) {
        const traceIdSql = Prisma.join(traceIds.map((value) => Prisma.sql`${value}`));
        riskPredicates.push(Prisma.sql`"executionId" IN (${traceIdSql})`);
      }
      if (rootExecutionIds.length > 0) {
        const rootExecutionSql = Prisma.join(rootExecutionIds.map((value) => Prisma.sql`${value}`));
        riskPredicates.push(Prisma.sql`"rootExecutionId" IN (${rootExecutionSql})`);
      }
      if (riskPredicates.length > 0) {
        await tx.$executeRaw(Prisma.sql`
          DELETE FROM "ExecutionRiskState"
          WHERE ${Prisma.join(riskPredicates, " OR ")}
        `);
      }
    }

    if (executionKeys.length > 0 || rootExecutionIds.length > 0 || identity.agentInstanceIds.length > 0) {
      const decisionWhere: Prisma.IntentDecisionWhereInput = {
        OR: [
          executionKeys.length > 0 ? { executionKey: { in: executionKeys } } : undefined,
          rootExecutionIds.length > 0 ? { rootExecutionId: { in: rootExecutionIds } } : undefined,
          identity.agentInstanceIds.length > 0 ? { agentInstanceId: { in: identity.agentInstanceIds } } : undefined,
        ].filter(Boolean) as Prisma.IntentDecisionWhereInput[],
      };
      if ((decisionWhere.OR || []).length > 0) {
        await tx.intentDecision.deleteMany({ where: decisionWhere });
      }
    }

    if ((executionIntentWhere.OR || []).length > 0) {
      await tx.executionIntent.deleteMany({ where: executionIntentWhere });
    }

    const traceDeleteCondition = buildScopedSqlCondition({
      ...identity,
      projectColumn: Prisma.sql`"projectId"`,
      agentInstanceColumn: Prisma.sql`"agentInstanceId"`,
      openclawAgentColumn: Prisma.sql`"openclawAgentId"`,
      openclawSessionIdColumn: Prisma.sql`"openclawSessionId"`,
      openclawSessionKeyColumn: Prisma.sql`"openclawSessionKey"`,
    });
    if (traceDeleteCondition) {
      await tx.$executeRaw(Prisma.sql`
        DELETE FROM "Trace"
        WHERE ${traceDeleteCondition}
      `);
    }

    const eventDeleteCondition = buildScopedSqlCondition({
      ...identity,
      projectColumn: Prisma.sql`"projectId"`,
      agentInstanceColumn: Prisma.sql`"agentInstanceId"`,
      openclawAgentColumn: Prisma.sql`"openclawAgentId"`,
      openclawSessionIdColumn: Prisma.sql`"openclawSessionId"`,
      openclawSessionKeyColumn: Prisma.sql`"openclawSessionKey"`,
    });
    if (eventDeleteCondition) {
      await tx.$executeRaw(Prisma.sql`
        DELETE FROM "TelemetryEvent"
        WHERE ${eventDeleteCondition}
      `);
    }

    if (rootExecutionIds.length > 0 || identity.openclawSessionKeys.length > 0) {
      const orphanPredicates: Prisma.Sql[] = [];
      if (rootExecutionIds.length > 0) {
        const rootExecutionSql = Prisma.join(rootExecutionIds.map((value) => Prisma.sql`${value}`));
        orphanPredicates.push(Prisma.sql`"rootExecutionId" IN (${rootExecutionSql})`);
      }
      if (identity.openclawSessionKeys.length > 0) {
        const sessionKeySql = Prisma.join(identity.openclawSessionKeys.map((value) => Prisma.sql`${value}`));
        orphanPredicates.push(Prisma.sql`"openclawSessionKey" IN (${sessionKeySql})`);
      }
      if (orphanPredicates.length > 0) {
        await tx.$executeRaw(Prisma.sql`
          DELETE FROM "TraceOrphan"
          WHERE ${Prisma.join(orphanPredicates, " OR ")}
        `);
      }
    }

    await tx.policyRule.deleteMany({
      where: {
        scopeLevel: "agent",
        managedAgentKey: normalizedKey,
      },
    });

    await tx.intentPolicyConfig.deleteMany({
      where: {
        scopeLevel: "agent",
        managedAgentKey: normalizedKey,
      },
    });

    await tx.managedAgent.delete({
      where: { agentKey: normalizedKey },
    });
  });
}
