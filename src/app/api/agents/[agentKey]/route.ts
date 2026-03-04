/**
 * @fileoverview ClawSight SIEM module: platform/src/app/api/agents/[agentKey]/route.ts.
 */
import { NextRequest, NextResponse } from "next/server";
import {
  authorizeAdminRequest,
  authorizeReadRequest,
  resolveProjectScope,
} from "@/lib/auth";
import { parseManagedAgentKey } from "@/lib/agents/identity";
import {
  deleteManagedAgentAndData,
  getManagedAgent,
  updateManagedAgent,
} from "@/lib/agents/repository";

type Params = { agentKey: string };

async function resolveParams(params: Promise<Params> | Params): Promise<Params> {
  return params instanceof Promise ? await params : params;
}

/**
 * Returns managed-agent profile by key.
 */
export async function GET(
  request: NextRequest,
  context: { params: Promise<Params> | Params },
) {
  try {
    const unauthorized = authorizeReadRequest(request);
    if (unauthorized) return unauthorized;
    const url = new URL(request.url);
    const includeSensitive =
      url.searchParams.get("includeSensitive") === "1" ||
      url.searchParams.get("includeSensitive") === "true";
    if (includeSensitive) {
      const unauthorizedAdmin = authorizeAdminRequest(request);
      if (unauthorizedAdmin) return unauthorizedAdmin;
    }

    const { agentKey } = await resolveParams(context.params);
    const decoded = decodeURIComponent(agentKey);
    const parsed = parseManagedAgentKey(decoded);
    const scope = resolveProjectScope(request, parsed?.projectId);
    if (scope.response) return scope.response;
    const item = await getManagedAgent(decoded);
    if (!item) {
      return NextResponse.json({ error: "agent not found" }, { status: 404 });
    }
    if (includeSensitive) {
      return NextResponse.json({ ok: true, data: item });
    }
    const sanitized = {
      id: item.id,
      agentKey: item.agentKey,
      displayName: item.displayName,
      reportedName: item.reportedName,
      sourceType: item.sourceType,
      projectId: item.projectId,
      agentInstanceId: item.agentInstanceId,
      openclawSessionId: item.openclawSessionId,
      openclawAgentId: item.openclawAgentId,
      policyProfile: item.policyProfile,
      firstSeenAt: item.firstSeenAt,
      lastSeenAt: item.lastSeenAt,
      lastBootstrapAt: item.lastBootstrapAt,
      createdAt: item.createdAt,
      updatedAt: item.updatedAt,
    };
    return NextResponse.json({ ok: true, data: sanitized });
  } catch (err) {
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}

/**
 * Updates editable managed-agent profile fields.
 */
export async function PATCH(
  request: NextRequest,
  context: { params: Promise<Params> | Params },
) {
  try {
    const unauthorized = authorizeAdminRequest(request);
    if (unauthorized) return unauthorized;

    const { agentKey } = await resolveParams(context.params);
    const decoded = decodeURIComponent(agentKey);
    const body = (await request.json()) as {
      displayName?: string;
      notes?: string;
      policyProfile?: string;
    };

    const updated = await updateManagedAgent({
      agentKey: decoded,
      displayName: body.displayName,
      notes: body.notes,
      policyProfile: body.policyProfile,
    });

    return NextResponse.json({ ok: true, data: updated });
  } catch (err) {
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}

/**
 * Hard-deletes a managed agent and all scoped persisted data.
 */
export async function DELETE(
  request: NextRequest,
  context: { params: Promise<Params> | Params },
) {
  try {
    const unauthorized = authorizeAdminRequest(request);
    if (unauthorized) return unauthorized;

    const { agentKey } = await resolveParams(context.params);
    const decoded = decodeURIComponent(agentKey);
    await deleteManagedAgentAndData(decoded);
    return NextResponse.json({ ok: true });
  } catch (err) {
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}
