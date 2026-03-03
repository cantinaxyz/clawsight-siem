/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/agents/filter.ts.
 */
import { Prisma } from "@prisma/client";
import { parseManagedAgentKey } from "@/lib/agents/identity";

function projectSql(projectColumn: Prisma.Sql, projectId: string): Prisma.Sql {
  if (projectId === "default") {
    return Prisma.sql`COALESCE(NULLIF(${projectColumn}, ''), 'default') = 'default'`;
  }
  return Prisma.sql`COALESCE(NULLIF(${projectColumn}, ''), 'default') = ${projectId}`;
}

/**
 * Builds a SQL predicate that scopes queries to a managed-agent identity.
 *
 * Used by raw SQL APIs where identity columns differ by table.
 */
export function buildManagedAgentSqlCondition(input: {
  agentKey?: string | null;
  projectColumn: Prisma.Sql;
  agentInstanceColumn: Prisma.Sql;
  sessionIdColumn: Prisma.Sql;
  openclawAgentColumn: Prisma.Sql;
  sessionKeyColumn: Prisma.Sql;
}): Prisma.Sql | null {
  const parsed = parseManagedAgentKey(input.agentKey);
  if (!parsed) return null;

  if (parsed.kind === "inst") {
    return Prisma.sql`(${projectSql(input.projectColumn, parsed.projectId)} AND ${input.agentInstanceColumn} = ${parsed.value})`;
  }

  if (parsed.kind === "oc") {
    return Prisma.sql`(${projectSql(input.projectColumn, parsed.projectId)} AND ${input.openclawAgentColumn} = ${parsed.value})`;
  }

  if (parsed.kind === "sid") {
    return Prisma.sql`(${projectSql(input.projectColumn, parsed.projectId)} AND ${input.sessionIdColumn} = ${parsed.value})`;
  }

  return Prisma.sql`(${projectSql(input.projectColumn, parsed.projectId)} AND ${input.sessionKeyColumn} = ${parsed.value})`;
}

function projectWhere(projectId: string): Prisma.TelemetryEventWhereInput {
  if (projectId === "default") {
    return {
      OR: [{ projectId: null }, { projectId: "" }, { projectId: "default" }],
    };
  }
  return { projectId };
}

/**
 * Builds Prisma `where` input for telemetry-event queries scoped to a managed agent.
 */
export function buildManagedAgentEventWhere(agentKey?: string | null): Prisma.TelemetryEventWhereInput | null {
  const parsed = parseManagedAgentKey(agentKey);
  if (!parsed) return null;

  if (parsed.kind === "inst") {
    return {
      AND: [projectWhere(parsed.projectId), { agentInstanceId: parsed.value }],
    };
  }

  if (parsed.kind === "oc") {
    return {
      AND: [projectWhere(parsed.projectId), { openclawAgentId: parsed.value }],
    };
  }

  if (parsed.kind === "sid") {
    return {
      AND: [projectWhere(parsed.projectId), { openclawSessionId: parsed.value }],
    };
  }

  return {
    AND: [projectWhere(parsed.projectId), { openclawSessionKey: parsed.value }],
  };
}
