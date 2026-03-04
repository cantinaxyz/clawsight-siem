/**
 * @fileoverview ClawSight SIEM module: platform/src/app/api/agents/[agentKey]/profile/route.ts.
 */
import { NextRequest, NextResponse } from "next/server";
import { authorizeAdminRequest } from "@/lib/auth";
import { updateManagedAgent } from "@/lib/agents/repository";

type Params = { agentKey: string };

async function resolveParams(params: Promise<Params> | Params): Promise<Params> {
  return params instanceof Promise ? await params : params;
}

export async function POST(
  request: NextRequest,
  context: { params: Promise<Params> | Params },
) {
  try {
    const unauthorized = authorizeAdminRequest(request);
    if (unauthorized) return unauthorized;

    const { agentKey } = await resolveParams(context.params);
    const decoded = decodeURIComponent(agentKey);
    const body = (await request.json()) as { policyProfile?: string };

    const data = await updateManagedAgent({
      agentKey: decoded,
      policyProfile: body.policyProfile,
    });
    return NextResponse.json({ ok: true, data });
  } catch (err) {
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}
