/**
 * @fileoverview ClawSight SIEM module: platform/src/app/api/intent/config/route.ts.
 */
import { NextRequest, NextResponse } from "next/server";
import { loadIntentPolicyConfig, saveIntentPolicyConfig, type IntentPolicyConfig } from "@/lib/intent-policy";

type ScopeLevel = "global" | "agent";

type ConfigBody = {
  scopeLevel?: ScopeLevel;
  managedAgentKey?: string | null;
  config?: Partial<IntentPolicyConfig>;
};

function parseScopeLevel(value: unknown): ScopeLevel {
  return value === "agent" ? "agent" : "global";
}

/**
 * Returns effective intent-policy config for global/agent scope.
 */
export async function GET(request: NextRequest) {
  try {
    const url = new URL(request.url);
    const scopeLevel = parseScopeLevel(url.searchParams.get("scopeLevel"));
    const managedAgentKey = url.searchParams.get("managedAgentKey");
    const config = await loadIntentPolicyConfig({
      scopeLevel,
      managedAgentKey,
      fallbackToGlobal: true,
    });
    return NextResponse.json({ ok: true, config });
  } catch (err) {
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}

/**
 * Saves intent-policy config for global/agent scope.
 */
export async function POST(request: NextRequest) {
  try {
    const body = (await request.json()) as ConfigBody;
    const scopeLevel = parseScopeLevel(body.scopeLevel);
    const managedAgentKey = typeof body.managedAgentKey === "string" ? body.managedAgentKey : null;
    const config = await saveIntentPolicyConfig(body.config || {}, {
      scopeLevel,
      managedAgentKey,
    });
    return NextResponse.json({ ok: true, config });
  } catch (err) {
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}
