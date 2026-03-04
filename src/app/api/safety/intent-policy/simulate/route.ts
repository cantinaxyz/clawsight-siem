/**
 * @fileoverview ClawSight SIEM module: platform/src/app/api/safety/intent-policy/simulate/route.ts.
 */
import { randomUUID } from "node:crypto";
import { NextResponse } from "next/server";
import { authorizeAdminRequest } from "@/lib/auth";
import { evaluateIntentAction, evaluateIntentBaseline, evaluateIntentOutput } from "@/lib/intent-policy";
import { prisma } from "@/lib/prisma";

type RunMode = "baseline" | "action" | "output" | "full";

type Body = {
  task?: string;
  toolName?: string;
  toolParams?: unknown;
  toolOutput?: string;
  run?: RunMode;
};

function parseToolParams(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return value as Record<string, unknown>;
}

/**
 * Runs intent-policy simulation (baseline/action/output/full) for UI sandbox testing.
 */
export async function POST(request: Request) {
  const rootExecutionId = `sim:${randomUUID()}`;
  try {
    const unauthorized = authorizeAdminRequest(request);
    if (unauthorized) return unauthorized;

    const body = (await request.json()) as Body;
    const task = String(body.task || "").trim();
    const toolName = String(body.toolName || "web_fetch").trim();
    const toolParams = parseToolParams(body.toolParams);
    const toolOutput = String(body.toolOutput || "");
    const run = body.run === "baseline" || body.run === "action" || body.run === "output" || body.run === "full"
      ? body.run
      : "full";

    const baseReq = {
      rootExecutionId,
      agentInstanceId: "simulator",
      managedAgentKey: undefined,
      sourceType: "system",
      prompt: task || "simulated task",
      requestId: `sim-${randomUUID().slice(0, 8)}`,
      traceId: rootExecutionId,
    };

    const result: {
      baseline?: Awaited<ReturnType<typeof evaluateIntentBaseline>>;
      action?: Awaited<ReturnType<typeof evaluateIntentAction>>;
      output?: Awaited<ReturnType<typeof evaluateIntentOutput>>;
    } = {};

    if (run === "baseline" || run === "full" || run === "action" || run === "output") {
      result.baseline = await evaluateIntentBaseline(baseReq);
    }
    if (run === "action" || run === "full") {
      result.action = await evaluateIntentAction({
        ...baseReq,
        toolName,
        params: toolParams,
      });
    }
    if ((run === "output" || run === "full") && toolOutput.trim()) {
      result.output = await evaluateIntentOutput({
        ...baseReq,
        toolName,
        content: toolOutput,
      });
    }

    return NextResponse.json({ ok: true, run, ...result });
  } catch (err) {
    return NextResponse.json({ error: String(err) }, { status: 500 });
  } finally {
    await prisma.$transaction([
      prisma.intentDecision.deleteMany({ where: { rootExecutionId } }),
      prisma.executionIntent.deleteMany({ where: { rootExecutionId } }),
    ]);
  }
}
