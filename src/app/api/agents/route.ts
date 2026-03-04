/**
 * @fileoverview ClawSight SIEM module: platform/src/app/api/agents/route.ts.
 */
import { NextRequest, NextResponse } from "next/server";
import { resolveProjectScope } from "@/lib/auth";
import { discoverManagedAgents } from "@/lib/agents/discovery";
import { listManagedAgents } from "@/lib/agents/repository";

export async function GET(request: NextRequest) {
  try {
    const url = new URL(request.url);
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

    return NextResponse.json({ ok: true, total: data.length, data });
  } catch (err) {
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}
