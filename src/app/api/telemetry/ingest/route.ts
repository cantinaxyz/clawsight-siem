/**
 * @fileoverview ClawSight SIEM module: platform/src/app/api/telemetry/ingest/route.ts.
 */
import crypto from "node:crypto";
import { NextResponse } from "next/server";
import { ingestEvents, type TelemetryInput } from "@/lib/telemetry";
import { authorizeIngestRequest } from "@/lib/auth";

function normalizeHeaderRequestId(req: Request): string | undefined {
  const value =
    req.headers.get("x-clawsight-request-id") ||
    req.headers.get("x-request-id");
  if (!value) {
    return undefined;
  }
  return value.trim();
}

function getClientIp(req: Request): string | undefined {
  const candidateHeaders = [
    "x-forwarded-for",
    "x-real-ip",
    "x-client-ip",
    "cf-connecting-ip",
    "x-forwarded",
  ];
  for (const header of candidateHeaders) {
    const value = req.headers.get(header);
    if (!value) continue;
    const candidate = value
      .split(",")[0]
      .trim()
      .replace(/\[(\d+\.\d+\.\d+\.\d+)\]/, "$1");
    if (candidate) return candidate;
  }
  return undefined;
}

function getClientHost(req: Request): string | undefined {
  const host =
    req.headers.get("x-forwarded-host") ||
    req.headers.get("host") ||
    req.headers.get(":authority") ||
    req.headers.get("referer");
  return host ?? undefined;
}

function getClientPort(req: Request): number | undefined {
  const headerPort =
    req.headers.get("x-forwarded-port")?.trim() || req.headers.get("x-real-port")?.trim() || "";
  if (headerPort) {
    const parsed = Number(headerPort);
    if (Number.isInteger(parsed) && parsed > 0) return parsed;
  }
  const host = req.headers.get("host");
  if (!host) {
    return undefined;
  }
  const colon = host.lastIndexOf(":");
  if (colon < 0) {
    return undefined;
  }
  const portCandidate = Number(host.slice(colon + 1));
  return Number.isInteger(portCandidate) ? portCandidate : undefined;
}

/**
 * Ingest endpoint for plugin telemetry envelopes.
 *
 * Performs auth, request metadata normalization, and delegates persistence to `ingestEvents`.
 */
export async function POST(req: Request) {
  try {
    const unauthorized = authorizeIngestRequest(req);
    if (unauthorized) {
      return unauthorized;
    }

    const body = (await req.json()) as unknown;
    const rawEvents = (body as { events?: unknown[] }).events;
    if (!Array.isArray(rawEvents)) {
      return NextResponse.json({ error: "Invalid payload: events[] required" }, { status: 400 });
    }

    const sourceIp = getClientIp(req);
    const sourceHost = getClientHost(req);
    const sourcePort = getClientPort(req);
    const ingressRequestId = normalizeHeaderRequestId(req) || crypto.randomUUID();

    const events: TelemetryInput[] = rawEvents
      .filter((e): e is Record<string, unknown> => Boolean(e) && typeof e === "object" && !Array.isArray(e))
      .map((e) => ({
        eventId: typeof e.eventId === "string" ? e.eventId : undefined,
        ts: typeof e.ts === "number" && Number.isFinite(e.ts) ? e.ts : Date.now(),
        category: typeof e.category === "string" ? e.category : "diagnostic",
        action: typeof e.action === "string" ? e.action : "event",
        severity: typeof e.severity === "string" ? e.severity : "info",
        projectId: typeof e.projectId === "string" ? e.projectId : undefined,
        agentInstanceId: typeof e.agentInstanceId === "string" ? e.agentInstanceId : undefined,
        agentName: typeof e.agentName === "string" ? e.agentName : undefined,
        correlationId: typeof e.correlationId === "string" ? e.correlationId : undefined,
        rootExecutionId: typeof e.rootExecutionId === "string" ? e.rootExecutionId : undefined,
        rootMessageId: typeof e.rootMessageId === "string" ? e.rootMessageId : undefined,
        traceId: typeof e.traceId === "string" ? e.traceId : undefined,
        spanId: typeof e.spanId === "string" ? e.spanId : undefined,
        parentSpanId: typeof e.parentSpanId === "string" ? e.parentSpanId : undefined,
        result: typeof e.result === "string" ? e.result : undefined,
        outcome: typeof e.outcome === "string" ? e.outcome : undefined,
        outcomeReason: typeof e.outcomeReason === "string" ? e.outcomeReason : undefined,
        policyRuleId: typeof e.policyRuleId === "string" ? e.policyRuleId : undefined,
        policyDecisionId: typeof e.policyDecisionId === "string" ? e.policyDecisionId : undefined,
        durationMs: typeof e.durationMs === "number" ? e.durationMs : undefined,
        latencyMs: typeof e.latencyMs === "number" ? e.latencyMs : undefined,
        errorClass: typeof e.errorClass === "string" ? e.errorClass : undefined,
        errorCode: typeof e.errorCode === "string" ? e.errorCode : undefined,
        toolExitCode: typeof e.toolExitCode === "number" ? e.toolExitCode : undefined,
        schemaVersion: typeof e.schemaVersion === "number" ? e.schemaVersion : undefined,
        openclaw:
          e.openclaw && typeof e.openclaw === "object"
            ? (e.openclaw as TelemetryInput["openclaw"])
            : {
                agentId: typeof e.openclawAgentId === "string" ? e.openclawAgentId : undefined,
                sessionKey:
                  typeof e.openclawSessionKey === "string"
                    ? e.openclawSessionKey
                    : typeof e.openclawSessionId === "string"
                      ? e.openclawSessionId
                      : undefined,
                sessionId:
                  typeof e.openclawSessionId === "string"
                    ? e.openclawSessionId
                    : typeof e.openclawSessionKey === "string"
                      ? e.openclawSessionKey
                      : undefined,
                runId: typeof e.openclawRunId === "string" ? e.openclawRunId : undefined,
                toolName: typeof e.openclawToolName === "string" ? e.openclawToolName : undefined,
                toolCallId: typeof e.openclawToolCallId === "string" ? e.openclawToolCallId : undefined,
              },
        payload: e.payload,
        traceOrphan: Boolean(
          e.traceOrphan === true ||
          (e.payload &&
          typeof e.payload === "object" &&
          !Array.isArray(e.payload) &&
          (e.payload as Record<string, unknown>).__traceOrphan === true),
        ),
        sourceIp,
        sourceHost,
        sourcePort,
        requestId: typeof e.requestId === "string" && e.requestId.trim() ? e.requestId : ingressRequestId,
      }));

    const result = await ingestEvents(events);
    return NextResponse.json({ ok: true, ...result }, { status: 201 });
  } catch (err) {
    return NextResponse.json({ error: `ingest failed: ${String(err)}` }, { status: 500 });
  }
}
