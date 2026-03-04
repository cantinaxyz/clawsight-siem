/**
 * @fileoverview ClawSight SIEM module: platform/src/app/api/agents/route.ts.
 */
import { NextRequest, NextResponse } from "next/server";
import {
  authorizeAdminRequest,
  authorizeReadRequest,
  resolveProjectScope,
} from "@/lib/auth";
import { discoverManagedAgents } from "@/lib/agents/discovery";
import { listManagedAgents } from "@/lib/agents/repository";

export async function GET(request: NextRequest) {
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
    const requestedProjectId = url.searchParams.get("projectId")?.trim() || undefined;
    const scope = resolveProjectScope(request, requestedProjectId);
    if (scope.response) return scope.response;
    const projectId = scope.projectId;
    const search = url.searchParams.get("search")?.trim() || url.searchParams.get("q")?.trim() || undefined;
    const limit = Number(url.searchParams.get("limit") || 100);

    await discoverManagedAgents(300);

    const data = await listManagedAgents({
      projectId,
      search,
      limit: Number.isFinite(limit) ? limit : 100,
    });
    if (includeSensitive) {
      return NextResponse.json({ ok: true, total: data.length, data });
    }

    const sanitized = data.map((agent) => ({
      id: agent.id,
      agentKey: agent.agentKey,
      displayName: agent.displayName,
      reportedName: agent.reportedName,
      sourceType: agent.sourceType,
      projectId: agent.projectId,
      agentInstanceId: agent.agentInstanceId,
      openclawSessionId: agent.openclawSessionId,
      openclawAgentId: agent.openclawAgentId,
      policyProfile: agent.policyProfile,
      firstSeenAt: agent.firstSeenAt,
      lastSeenAt: agent.lastSeenAt,
      lastBootstrapAt: agent.lastBootstrapAt,
      createdAt: agent.createdAt,
      updatedAt: agent.updatedAt,
    }));

    return NextResponse.json({ ok: true, total: sanitized.length, data: sanitized });
  } catch (err) {
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}
