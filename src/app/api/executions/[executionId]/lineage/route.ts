/**
 * @fileoverview ClawSight SIEM module: platform/src/app/api/executions/[executionId]/lineage/route.ts.
 */
import { Prisma } from "@prisma/client";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { resolveOutcome, resolveTriggerType, type ExecutionTraceRow } from "@/lib/executions/mapper";
import type { ExecutionLineageNode } from "@/lib/executions/types";

export const dynamic = "force-dynamic";

type ParamsInput = { executionId: string };

async function resolveParams(params: ParamsInput | Promise<ParamsInput>): Promise<ParamsInput> {
  return Promise.resolve(params);
}

function toNode(row: ExecutionTraceRow): ExecutionLineageNode {
  return {
    executionId: row.traceId,
    traceId: row.traceId,
    triggerType: resolveTriggerType(row),
    outcome: resolveOutcome(row),
    durationMs: row.durationMs ?? undefined,
    startedAt: row.startedAt.toISOString(),
    children: [],
  };
}

/**
 * Returns execution lineage rooted at the selected execution/rootExecutionId.
 */
export async function GET(
  _request: NextRequest,
  context: { params: ParamsInput | Promise<ParamsInput> },
) {
  try {
    const { executionId } = await resolveParams(context.params);
    const decoded = decodeURIComponent(String(executionId || "").trim());
    if (!decoded) {
      return NextResponse.json({ ok: false, error: "executionId required" }, { status: 400 });
    }

    const currentRows = await prisma.$queryRaw<ExecutionTraceRow[]>(Prisma.sql`
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
      WHERE "traceId" = ${decoded}
      LIMIT 1
    `);

    const current = currentRows[0];
    if (!current) {
      return NextResponse.json({ ok: false, error: "execution not found" }, { status: 404 });
    }

    const lineageRootId = current.rootExecutionId || current.traceId;
    const lineageRows = await prisma.$queryRaw<ExecutionTraceRow[]>(Prisma.sql`
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
      WHERE "traceId" = ${lineageRootId}
         OR "rootExecutionId" = ${lineageRootId}
      ORDER BY "startedAt" ASC
      LIMIT 250
    `);

    const rootRow = lineageRows.find((row) => row.traceId === lineageRootId) || current;
    const rootNode = toNode(rootRow);

    for (const row of lineageRows) {
      if (row.traceId === rootNode.executionId) continue;
      rootNode.children.push(toNode(row));
    }

    return NextResponse.json({ ok: true, data: rootNode });
  } catch (error) {
    return NextResponse.json({ ok: false, error: String(error) }, { status: 500 });
  }
}
