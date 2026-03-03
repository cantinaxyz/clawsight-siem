/**
 * @fileoverview ClawSight SIEM module: platform/src/app/api/v1/payments/send/route.ts.
 */
import { NextResponse } from "next/server";
import { authorizeRequest } from "@/lib/auth";

export async function POST(req: Request) {
  try {
    const unauthorized = authorizeRequest(req);
    if (unauthorized) {
      return unauthorized;
    }
    return NextResponse.json(
      {
        error: "payments.send is disabled in this telemetry-focused MVP",
      },
      { status: 410 },
    );
  } catch (err) {
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}
