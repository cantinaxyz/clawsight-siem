/**
 * @fileoverview ClawSight SIEM module: platform/src/app/api/safety/config/route.ts.
 */
import { NextResponse } from "next/server";
import { authorizeAdminRequest } from "@/lib/auth";
import { applySafetyConfig, configFromMode, loadSafetyConfig, type SafetyMode } from "@/lib/safety-config";

type Body = {
  mode?: SafetyMode;
  config?: unknown;
};

function parseMode(value: unknown): SafetyMode | null {
  if (value === "relaxed" || value === "balanced" || value === "strict") {
    return value;
  }
  return null;
}

/**
 * Returns effective global safety config for dashboard/safety UI.
 */
export async function GET(req: Request) {
  try {
    const unauthorized = authorizeAdminRequest(req);
    if (unauthorized) return unauthorized;
    const config = await loadSafetyConfig();
    return NextResponse.json({ ok: true, config });
  } catch (err) {
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}

/**
 * Applies safety mode preset or full safety config payload.
 */
export async function POST(req: Request) {
  try {
    const unauthorized = authorizeAdminRequest(req);
    if (unauthorized) return unauthorized;

    const body = (await req.json()) as Body;
    const mode = parseMode(body.mode);
    if (mode) {
      const next = await applySafetyConfig(configFromMode(mode));
      return NextResponse.json({ ok: true, config: next });
    }

    if (body.config && typeof body.config === "object") {
      const next = await applySafetyConfig(body.config as Parameters<typeof applySafetyConfig>[0]);
      return NextResponse.json({ ok: true, config: next });
    }

    return NextResponse.json({ error: "Invalid payload" }, { status: 400 });
  } catch (err) {
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}
