/**
 * @fileoverview ClawSight SIEM module: platform/src/app/api/admin/alerts/migrate-v2/route.ts.
 */
import { NextRequest, NextResponse } from "next/server";
import { migrateLegacyAlertsToExecutionV2 } from "@/lib/alerts/migrate-to-execution-v2";

export async function POST(request: NextRequest) {
  try {
    const token = process.env.ALERT_MIGRATION_TOKEN;
    if (token) {
      const auth = request.headers.get("authorization") || "";
      const provided = auth.startsWith("Bearer ") ? auth.slice("Bearer ".length).trim() : "";
      if (!provided || provided !== token) {
        return NextResponse.json({ ok: false, error: "unauthorized" }, { status: 401 });
      }
    }

    const body = (await request.json().catch(() => ({}))) as { dryRun?: boolean };
    const result = await migrateLegacyAlertsToExecutionV2({ dryRun: Boolean(body?.dryRun) });
    return NextResponse.json({ ok: true, result });
  } catch (error) {
    return NextResponse.json({ ok: false, error: String(error) }, { status: 500 });
  }
}
