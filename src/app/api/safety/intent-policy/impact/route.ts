/**
 * @fileoverview ClawSight SIEM module: platform/src/app/api/safety/intent-policy/impact/route.ts.
 */
import { Prisma } from "@prisma/client";
import { NextRequest, NextResponse } from "next/server";
import { authorizeAdminRequest } from "@/lib/auth";
import { prisma } from "@/lib/prisma";

export async function GET(request: NextRequest) {
  try {
    const unauthorized = authorizeAdminRequest(request);
    if (unauthorized) return unauthorized;
    const url = new URL(request.url);
    const window = url.searchParams.get("window") || "24h";
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);

    const [executionsRows, decisionRows, sanitizedRows, baselineRows, alignmentRows, tokenRows] = await Promise.all([
      prisma.$queryRaw<Array<{ count: bigint }>>(Prisma.sql`
        SELECT COUNT(*)::bigint AS count
        FROM "ExecutionIntent"
        WHERE "updatedAt" >= ${since}
      `),
      prisma.$queryRaw<Array<{ action: string; count: bigint }>>(Prisma.sql`
        SELECT "action", COUNT(*)::bigint AS count
        FROM "IntentDecision"
        WHERE "createdAt" >= ${since}
        GROUP BY "action"
      `),
      prisma.$queryRaw<Array<{ count: bigint }>>(Prisma.sql`
        SELECT COUNT(*)::bigint AS count
        FROM "IntentDecision"
        WHERE "createdAt" >= ${since}
          AND "phase" = 'tool_output'
          AND "action" = 'modify'
      `),
      prisma.$queryRaw<Array<{ count: bigint }>>(Prisma.sql`
        SELECT COUNT(*)::bigint AS count
        FROM "IntentDecision"
        WHERE "createdAt" >= ${since}
          AND "phase" = 'baseline'
          AND "signals"::text ILIKE '%intent.baseline.llm%'
      `),
      prisma.$queryRaw<Array<{ count: bigint }>>(Prisma.sql`
        SELECT COUNT(*)::bigint AS count
        FROM "IntentDecision"
        WHERE "createdAt" >= ${since}
          AND "phase" = 'tool_call'
          AND "signals"::text ILIKE '%llm.alignment%'
      `),
      prisma.$queryRaw<Array<{ input_tokens: bigint; output_tokens: bigint; total_tokens: bigint }>>(Prisma.sql`
        SELECT
          COALESCE(SUM(CASE
            WHEN ("details"->'llmUsage'->>'input') ~ '^[0-9]+$'
            THEN ("details"->'llmUsage'->>'input')::bigint
            ELSE 0
          END), 0)::bigint AS input_tokens,
          COALESCE(SUM(CASE
            WHEN ("details"->'llmUsage'->>'output') ~ '^[0-9]+$'
            THEN ("details"->'llmUsage'->>'output')::bigint
            ELSE 0
          END), 0)::bigint AS output_tokens,
          COALESCE(SUM(CASE
            WHEN ("details"->'llmUsage'->>'total') ~ '^[0-9]+$'
            THEN ("details"->'llmUsage'->>'total')::bigint
            ELSE 0
          END), 0)::bigint AS total_tokens
        FROM "IntentDecision"
        WHERE "createdAt" >= ${since}
      `),
    ]);

    const warn = decisionRows.find((row) => row.action === "warn")?.count ?? 0n;
    const block = decisionRows.find((row) => row.action === "block")?.count ?? 0n;

    const llmTokenSummary = tokenRows[0] ?? {
      input_tokens: 0n,
      output_tokens: 0n,
      total_tokens: 0n,
    };

    return NextResponse.json({
      ok: true,
      impact: {
        window: window === "24h" ? "24h" : "24h",
        executionsEvaluated: Number(executionsRows[0]?.count ?? 0n),
        decisionsWarn: Number(warn),
        decisionsBlock: Number(block),
        outputsSanitized: Number(sanitizedRows[0]?.count ?? 0n),
        llmCallsBaseline: Number(baselineRows[0]?.count ?? 0n),
        llmCallsAlignment: Number(alignmentRows[0]?.count ?? 0n),
        llmCallsOutput: 0,
        llmTokensInput: Number(llmTokenSummary.input_tokens ?? 0n),
        llmTokensOutput: Number(llmTokenSummary.output_tokens ?? 0n),
        llmTokensTotal: Number(llmTokenSummary.total_tokens ?? 0n),
      },
    });
  } catch (err) {
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}
