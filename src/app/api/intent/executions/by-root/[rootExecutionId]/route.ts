/**
 * @fileoverview ClawSight SIEM module: platform/src/app/api/intent/executions/by-root/[rootExecutionId]/route.ts.
 */
import { Prisma } from "@prisma/client";
import { NextRequest, NextResponse } from "next/server";
import {
  authorizeAdminRequest,
  authorizeReadRequest,
  resolveProjectScope,
} from "@/lib/auth";
import { prisma } from "@/lib/prisma";
import {
  loadExecutionIntentByRoot,
  patchExecutionIntentBaseline,
  type IntentScope,
} from "@/lib/intent-policy";

type Params = { rootExecutionId: string };

async function resolveParams(input: Params | Promise<Params>): Promise<Params> {
  return Promise.resolve(input);
}

export const dynamic = "force-dynamic";

function normalizeProjectId(value: unknown): string {
  const normalized = String(value ?? "").trim().toLowerCase();
  return normalized || "default";
}

function toScopes(value: unknown): IntentScope[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => String(item || "").trim().toLowerCase())
    .filter((item): item is IntentScope =>
      item === "filesystem_read" ||
      item === "filesystem_write" ||
      item === "network_read" ||
      item === "network_write" ||
      item === "execution" ||
      item === "messaging" ||
      item === "credentials_access" ||
      item === "payment" ||
      item === "skill_install" ||
      item === "scheduler",
    );
}

/**
 * Returns execution baseline + decision timeline for a root execution id.
 */
export async function GET(
  request: NextRequest,
  context: { params: Params | Promise<Params> },
) {
  try {
    const unauthorized = authorizeReadRequest(request);
    if (unauthorized) return unauthorized;

    const url = new URL(request.url);
    const requestedProjectId = url.searchParams.get("projectId")?.trim() || undefined;
    const scope = resolveProjectScope(request, requestedProjectId);
    if (scope.response) return scope.response;

    const { rootExecutionId } = await resolveParams(context.params);
    const root = decodeURIComponent(String(rootExecutionId || "").trim());
    if (!root) {
      return NextResponse.json({ error: "rootExecutionId required" }, { status: 400 });
    }

    const agentInstanceId = url.searchParams.get("agentInstanceId") || undefined;
    const execution = await loadExecutionIntentByRoot(root, agentInstanceId);
    if (!execution) {
      return NextResponse.json({ ok: true, execution: null, decisions: [] });
    }
    if (
      scope.projectId &&
      normalizeProjectId((execution as { projectId?: string | null }).projectId) !== scope.projectId
    ) {
      return NextResponse.json({ ok: true, execution: null, decisions: [] });
    }

    const decisions = await prisma.$queryRaw<Array<{
      id: number;
      phase: string;
      action: string;
      scoreDelta: number;
      driftScore: number;
      confidence: number | null;
      reason: string | null;
      toolName: string | null;
      targetDomain: string | null;
      signals: unknown;
      details: unknown;
      createdAt: Date;
    }>>(Prisma.sql`
      SELECT
        "id", "phase", "action", "scoreDelta", "driftScore", "confidence", "reason",
        "toolName", "targetDomain", "signals", "details", "createdAt"
      FROM "IntentDecision"
      WHERE "executionKey" = ${execution.executionKey}
      ORDER BY "createdAt" ASC, "id" ASC
      LIMIT 400
    `);

    return NextResponse.json({
      ok: true,
      execution,
      decisions: decisions.map((row) => ({
        ...row,
        createdAt: row.createdAt.toISOString(),
      })),
    });
  } catch (err) {
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}

/**
 * Applies operator baseline patch (boundary/scopes/domains) for an execution root.
 */
export async function PATCH(
  request: NextRequest,
  context: { params: Params | Promise<Params> },
) {
  try {
    const unauthorized = authorizeAdminRequest(request);
    if (unauthorized) return unauthorized;

    const url = new URL(request.url);
    const requestedProjectId = url.searchParams.get("projectId")?.trim() || undefined;
    const scope = resolveProjectScope(request, requestedProjectId);
    if (scope.response) return scope.response;

    const { rootExecutionId } = await resolveParams(context.params);
    const root = decodeURIComponent(String(rootExecutionId || "").trim());
    if (!root) {
      return NextResponse.json({ error: "rootExecutionId required" }, { status: 400 });
    }

    const body = (await request.json()) as {
      agentInstanceId?: string | null;
      taskBoundary?: string;
      expectedScopes?: unknown;
      expectedDomains?: unknown;
      patchedBy?: string;
      reason?: string;
      recompute?: boolean;
    };
    const current = await loadExecutionIntentByRoot(
      root,
      typeof body.agentInstanceId === "string" ? body.agentInstanceId : undefined,
    );
    if (!current) {
      return NextResponse.json({ error: "execution intent not found" }, { status: 404 });
    }
    if (
      scope.projectId &&
      normalizeProjectId((current as { projectId?: string | null }).projectId) !== scope.projectId
    ) {
      return NextResponse.json({ error: "Forbidden: project scope mismatch" }, { status: 403 });
    }

    const next = await patchExecutionIntentBaseline({
      rootExecutionId: root,
      agentInstanceId: typeof body.agentInstanceId === "string" ? body.agentInstanceId : null,
      taskBoundary: typeof body.taskBoundary === "string" ? body.taskBoundary : undefined,
      expectedScopes: body.expectedScopes === undefined ? undefined : toScopes(body.expectedScopes),
      expectedDomains:
        body.expectedDomains === undefined
          ? undefined
          : Array.isArray(body.expectedDomains)
            ? body.expectedDomains.map((item) => String(item || "")).filter(Boolean)
            : [],
      patchedBy: typeof body.patchedBy === "string" ? body.patchedBy : undefined,
      reason: typeof body.reason === "string" ? body.reason : undefined,
      recompute: Boolean(body.recompute),
    });

    if (!next) {
      return NextResponse.json({ error: "execution intent not found" }, { status: 404 });
    }

    return NextResponse.json({ ok: true, execution: next });
  } catch (err) {
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}
