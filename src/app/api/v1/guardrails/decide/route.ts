/**
 * @fileoverview ClawSight SIEM module: platform/src/app/api/v1/guardrails/decide/route.ts.
 */
import { NextResponse } from "next/server";
import { evaluateMessageDecision, evaluateToolDecision } from "@/lib/policy";
import { evaluateIntentAction, evaluateIntentBaseline, evaluateIntentOutput } from "@/lib/intent-policy";
import { evaluatePromptInjectionGuard } from "@/lib/prompt-injection";
import { authorizeIngestRequest } from "@/lib/auth";

type Body = {
  kind?: "tool" | "message" | "inbound_message" | "intent_baseline" | "intent_action" | "intent_output";
  [key: string]: unknown;
};

export async function POST(req: Request) {
  try {
    const unauthorized = authorizeIngestRequest(req);
    if (unauthorized) {
      return unauthorized;
    }

    const body = (await req.json()) as Body;
    const kind = body?.kind;

    if (kind === "intent_baseline") {
      const decision = await evaluateIntentBaseline(body as Parameters<typeof evaluateIntentBaseline>[0]);
      return NextResponse.json(decision);
    }

    if (kind === "intent_action") {
      const decision = await evaluateIntentAction(body as Parameters<typeof evaluateIntentAction>[0]);
      return NextResponse.json(decision);
    }

    if (kind === "intent_output") {
      const decision = await evaluateIntentOutput(body as Parameters<typeof evaluateIntentOutput>[0]);
      return NextResponse.json(decision);
    }

    if (kind === "tool") {
      const record = body as Record<string, unknown>;
      const decision = await evaluateToolDecision(record);
      return NextResponse.json({
        action: decision.action,
        decisionId: decision.decisionId,
        ruleId: decision.ruleId,
        reason: decision.reason,
        params: decision.params,
      });
    }

    if (kind === "inbound_message") {
      const record = body as Record<string, unknown>;
      const content = typeof record.content === "string" ? record.content : "";
      const decision = await evaluatePromptInjectionGuard({
        surface: "inbound_message",
        requestId: typeof record.requestId === "string" ? record.requestId : undefined,
        sessionKey:
          typeof record.sessionKey === "string"
            ? record.sessionKey
            : typeof record.conversationId === "string"
              ? record.conversationId
              : undefined,
        channelId: typeof record.channelId === "string" ? record.channelId : undefined,
        sender:
          typeof record.from === "string"
            ? record.from
            : typeof record.sender === "string"
              ? record.sender
              : undefined,
        content,
      });
      return NextResponse.json({
        action: decision.action,
        decisionId: decision.decisionId,
        ruleId: decision.ruleId,
        reason: decision.reason,
        enforcement: decision.enforcement,
        signals: decision.signals,
      });
    }

    if (kind === "message") {
      const decision = await evaluateMessageDecision(body as Record<string, unknown>);
      return NextResponse.json({
        action: decision.action,
        decisionId: decision.decisionId,
        ruleId: decision.ruleId,
        reason: decision.reason,
        content: decision.content,
      });
    }

    return NextResponse.json({ error: "Unsupported kind" }, { status: 400 });
  } catch (err) {
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}
