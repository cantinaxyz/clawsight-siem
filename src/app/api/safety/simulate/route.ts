/**
 * @fileoverview ClawSight SIEM module: platform/src/app/api/safety/simulate/route.ts.
 */
import { NextResponse } from "next/server";
import { authorizeAdminRequest } from "@/lib/auth";
import { evaluateMessageDecision, evaluateToolDecision } from "@/lib/policy";
import { buildToolInspectionContent, evaluatePromptInjectionGuard } from "@/lib/prompt-injection";

type Body = {
  kind?: "tool" | "message" | "inbound_message";
  toolName?: string;
  params?: Record<string, unknown>;
  channelId?: string;
  to?: string;
  from?: string;
  content?: string;
  requestId?: string;
  sessionKey?: string;
};

/**
 * Runs static policy + prompt-injection simulation for tool/message/inbound payloads.
 */
export async function POST(req: Request) {
  try {
    const unauthorized = authorizeAdminRequest(req);
    if (unauthorized) return unauthorized;

    const body = (await req.json()) as Body;
    if (body.kind === "tool") {
      const payload: Record<string, unknown> = {
        kind: "tool",
        toolName: body.toolName || "",
        params: body.params || {},
        requestId: body.requestId,
        sessionKey: body.sessionKey,
      };
      const [promptDecision, policyDecision] = await Promise.all([
        evaluatePromptInjectionGuard({
          surface: "tool_call",
          requestId: body.requestId,
          sessionKey: body.sessionKey,
          toolName: body.toolName,
          content: buildToolInspectionContent(payload),
        }),
        evaluateToolDecision(payload),
      ]);
      return NextResponse.json({
        kind: "tool",
        promptInjection: promptDecision,
        policy: policyDecision,
      });
    }

    if (body.kind === "message") {
      const payload: Record<string, unknown> = {
        kind: "message",
        channelId: body.channelId || "",
        to: body.to || "",
        content: body.content || "",
        requestId: body.requestId,
      };
      const decision = await evaluateMessageDecision(payload);
      return NextResponse.json({ kind: "message", policy: decision });
    }

    if (body.kind === "inbound_message") {
      const decision = await evaluatePromptInjectionGuard({
        surface: "inbound_message",
        requestId: body.requestId,
        sessionKey: body.sessionKey,
        channelId: body.channelId,
        sender: body.from,
        content: body.content || "",
      });
      return NextResponse.json({ kind: "inbound_message", promptInjection: decision });
    }

    return NextResponse.json({ error: "Unsupported kind" }, { status: 400 });
  } catch (err) {
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}
