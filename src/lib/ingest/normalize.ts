/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/ingest/normalize.ts.
 */
import crypto from "node:crypto";
import { Prisma } from "@prisma/client";
import { redactPayload } from "@/lib/ingest/redact";
import { extractObservables, type ExtractedObservable } from "@/lib/ingest/observables";
import { extractOpenClawPayloadContext } from "@/lib/traces/lifecycle";

type OpenClawContext = {
  agentId?: string;
  sessionKey?: string;
  sessionId?: string;
  runId?: string;
  toolName?: string;
  toolCallId?: string;
  gatewayPort?: number;
};

export type NormalizeTelemetryInput = {
  eventId?: string;
  ts: number;
  category: string;
  action: string;
  severity?: string;
  projectId?: string;
  agentInstanceId?: string;
  agentName?: string;
  requestId?: string;
  correlationId?: string;
  rootExecutionId?: string;
  rootMessageId?: string;
  traceId?: string;
  spanId?: string;
  parentSpanId?: string;
  result?: string;
  outcome?: string;
  outcomeReason?: string;
  policyRuleId?: string;
  policyDecisionId?: string;
  durationMs?: number;
  latencyMs?: number;
  errorClass?: string;
  errorCode?: string;
  toolExitCode?: number;
  schemaVersion?: number;
  openclaw?: OpenClawContext;
  payload?: unknown;
  sourceIp?: string;
  sourceHost?: string;
  sourcePort?: number;
  traceOrphan?: boolean;
};

export type NormalizedTelemetryEnvelope = {
  row: Prisma.TelemetryEventCreateManyInput;
  detectionPayload: Prisma.InputJsonValue;
  observables: ExtractedObservable[];
};

type PayloadMap = Record<string, unknown> | null;
const DEFAULT_MAX_PAST_TS_SKEW_MS = 24 * 60 * 60 * 1000;
const DEFAULT_MAX_FUTURE_TS_SKEW_MS = 5 * 60 * 1000;
const MAX_TS_SKEW_MS_CAP = 30 * 24 * 60 * 60 * 1000;

function parseSkewMs(raw: string | undefined, fallback: number): number {
  if (!raw?.trim()) return fallback;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed < 0) return fallback;
  return Math.min(MAX_TS_SKEW_MS_CAP, Math.floor(parsed));
}

const MAX_EVENT_TS_PAST_SKEW_MS = parseSkewMs(
  process.env.SIEM_EVENT_TS_MAX_PAST_SKEW_MS || process.env.CLAWSIGHT_EVENT_TS_MAX_PAST_SKEW_MS,
  DEFAULT_MAX_PAST_TS_SKEW_MS,
);

const MAX_EVENT_TS_FUTURE_SKEW_MS = parseSkewMs(
  process.env.SIEM_EVENT_TS_MAX_FUTURE_SKEW_MS || process.env.CLAWSIGHT_EVENT_TS_MAX_FUTURE_SKEW_MS,
  DEFAULT_MAX_FUTURE_TS_SKEW_MS,
);

function toInt(value: unknown): number | null {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  return Math.trunc(value);
}

function asPayloadRecord(payload: unknown): PayloadMap {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return null;
  }
  return payload as PayloadMap;
}

function normalizeTimestamp(ts: number): Date {
  const nowMs = Date.now();
  if (!Number.isFinite(ts)) return new Date(nowMs);
  const candidate = Math.trunc(ts);
  const minAllowed = nowMs - MAX_EVENT_TS_PAST_SKEW_MS;
  const maxAllowed = nowMs + MAX_EVENT_TS_FUTURE_SKEW_MS;
  const bounded = Math.max(minAllowed, Math.min(maxAllowed, candidate));
  const parsed = new Date(bounded);
  return Number.isNaN(parsed.getTime()) ? new Date() : parsed;
}

function normalizeOutcome(raw?: string | null): string | null {
  const value = String(raw || "").trim().toLowerCase();
  if (!value) return null;
  if (value === "allow" || value === "ok" || value === "success" || value === "submitted") return "allow";
  if (value === "warn" || value === "warning") return "warn";
  if (value === "block" || value === "blocked" || value === "deny" || value === "denied") return "block";
  if (value === "modify" || value === "modified") return "modify";
  if (value === "error" || value === "fail" || value === "failed") return "error";
  return "unknown";
}

function toLegacyResult(outcome: string | null): string | null {
  if (!outcome) return null;
  if (outcome === "allow") return "ok";
  if (outcome === "warn") return "warn";
  if (outcome === "block") return "blocked";
  if (outcome === "modify") return "modified";
  if (outcome === "error") return "error";
  return null;
}

function resolveOutcome(input: NormalizeTelemetryInput, payload: PayloadMap): string | null {
  const fromTopLevel =
    normalizeOutcome(input.outcome) ||
    normalizeOutcome(input.result) ||
    normalizeOutcome(typeof payload?.result === "string" ? payload.result : null);

  if (fromTopLevel) return fromTopLevel;

  const fromPolicyDecision = payload && typeof payload.policyDecision === "object" && payload.policyDecision
    ? normalizeOutcome((payload.policyDecision as Record<string, unknown>).action as string)
    : null;
  if (fromPolicyDecision) return fromPolicyDecision;

  if (typeof payload?.error === "string" && payload.error.trim()) {
    return "error";
  }

  return null;
}

function resolveOutcomeReason(input: NormalizeTelemetryInput, payload: PayloadMap): string | null {
  const reason =
    input.outcomeReason ||
    (typeof payload?.reason === "string" ? payload.reason : undefined) ||
    (payload &&
    typeof payload.policyDecision === "object" &&
    payload.policyDecision &&
    typeof (payload.policyDecision as Record<string, unknown>).reason === "string"
      ? ((payload.policyDecision as Record<string, unknown>).reason as string)
      : undefined) ||
    (typeof payload?.error === "string" ? payload.error : undefined);
  return reason?.trim() || null;
}

function resolvePolicyRuleId(input: NormalizeTelemetryInput, payload: PayloadMap): string | null {
  const value =
    input.policyRuleId ||
    (typeof payload?.ruleId === "string" ? payload.ruleId : undefined) ||
    (payload &&
    typeof payload.policyDecision === "object" &&
    payload.policyDecision &&
    typeof (payload.policyDecision as Record<string, unknown>).ruleId === "string"
      ? ((payload.policyDecision as Record<string, unknown>).ruleId as string)
      : undefined);
  return value?.trim() || null;
}

function resolvePolicyDecisionId(input: NormalizeTelemetryInput, payload: PayloadMap): string | null {
  const value =
    input.policyDecisionId ||
    (typeof payload?.decisionId === "string" ? payload.decisionId : undefined) ||
    (payload &&
    typeof payload.policyDecision === "object" &&
    payload.policyDecision &&
    typeof (payload.policyDecision as Record<string, unknown>).decisionId === "string"
      ? ((payload.policyDecision as Record<string, unknown>).decisionId as string)
      : undefined);
  return value?.trim() || null;
}

function resolveLatencyMs(input: NormalizeTelemetryInput, payload: PayloadMap): number | null {
  return (
    toInt(input.latencyMs) ||
    (payload &&
    typeof payload.policyDecision === "object" &&
    payload.policyDecision &&
    typeof (payload.policyDecision as Record<string, unknown>).latencyMs === "number"
      ? toInt((payload.policyDecision as Record<string, unknown>).latencyMs)
      : null) ||
    null
  );
}

function resolveRequestId(input: NormalizeTelemetryInput, payload: PayloadMap): string | null {
  const value =
    input.requestId ||
    (typeof payload?.requestId === "string" ? payload.requestId : undefined) ||
    (payload &&
    typeof payload.policyDecision === "object" &&
    payload.policyDecision &&
    typeof (payload.policyDecision as Record<string, unknown>).requestId === "string"
      ? ((payload.policyDecision as Record<string, unknown>).requestId as string)
      : undefined);
  return value?.trim() || null;
}

function resolveAgentName(input: NormalizeTelemetryInput, payload: PayloadMap): string | null {
  const payloadProfile =
    payload?.agentProfile && typeof payload.agentProfile === "object" && !Array.isArray(payload.agentProfile)
      ? (payload.agentProfile as Record<string, unknown>)
      : null;
  const value =
    input.agentName ||
    (typeof payload?.agentName === "string" ? payload.agentName : undefined) ||
    (typeof payloadProfile?.agentName === "string" ? payloadProfile.agentName : undefined) ||
    (typeof payloadProfile?.name === "string" ? payloadProfile.name : undefined);
  return value?.trim() || null;
}

function asIdString(value: unknown): string | null {
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : null;
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return String(Math.trunc(value));
  }
  return null;
}

function safeTraceSegment(raw?: string | null): string {
  const normalized = String(raw || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._:@-]+/g, "_")
    .slice(0, 120);
  return normalized || "session";
}

function resolveOpenClawContext(input: NormalizeTelemetryInput, payload: PayloadMap) {
  const payloadCtx = extractOpenClawPayloadContext(payload);
  return {
    agentId: input.openclaw?.agentId?.trim() || null,
    sessionKey: input.openclaw?.sessionKey?.trim() || payloadCtx.sessionKey || null,
    sessionId: input.openclaw?.sessionId?.trim() || payloadCtx.sessionId || null,
    runId: input.openclaw?.runId?.trim() || payloadCtx.runId || null,
    toolName: input.openclaw?.toolName?.trim() || payloadCtx.toolName || null,
    toolCallId: input.openclaw?.toolCallId?.trim() || payloadCtx.toolCallId || null,
    gatewayPort: toInt(input.openclaw?.gatewayPort),
  };
}

function resolveRootMessageId(input: NormalizeTelemetryInput, payload: PayloadMap): string | null {
  const payloadMetadata =
    payload?.metadata && typeof payload.metadata === "object" && !Array.isArray(payload.metadata)
      ? (payload.metadata as Record<string, unknown>)
      : null;
  const value =
    input.rootMessageId ||
    asIdString(payload?.rootMessageId) ||
    asIdString(payload?.root_message_id) ||
    asIdString(payload?.messageId) ||
    asIdString(payload?.message_id) ||
    asIdString(payloadMetadata?.rootMessageId) ||
    asIdString(payloadMetadata?.root_message_id) ||
    asIdString(payloadMetadata?.messageId) ||
    asIdString(payloadMetadata?.message_id) ||
    null;
  return value?.trim() || null;
}

function resolveRootExecutionId(
  input: NormalizeTelemetryInput,
  payload: PayloadMap,
  rootMessageId: string | null,
  openclawCtx: ReturnType<typeof resolveOpenClawContext>,
): string | null {
  const explicit =
    input.rootExecutionId ||
    (typeof payload?.rootExecutionId === "string" ? payload.rootExecutionId : undefined) ||
    (typeof payload?.root_execution_id === "string" ? payload.root_execution_id : undefined);
  if (explicit?.trim()) {
    return explicit.trim();
  }
  if (!rootMessageId) {
    return null;
  }
  const channel = safeTraceSegment(openclawCtx.sessionKey || openclawCtx.sessionId || openclawCtx.runId);
  const conversation = safeTraceSegment(openclawCtx.sessionId || openclawCtx.sessionKey || openclawCtx.runId);
  return `msg:${channel}:${conversation}:${rootMessageId}`;
}

function resolveParentSpanId(input: NormalizeTelemetryInput, payload: PayloadMap): string | null {
  const value =
    input.parentSpanId ||
    (typeof payload?.parentSpanId === "string" ? payload.parentSpanId : undefined) ||
    (typeof payload?.parent_span_id === "string" ? payload.parent_span_id : undefined);
  return value?.trim() || null;
}

function resolveTraceId(input: NormalizeTelemetryInput, params: {
  payload: PayloadMap;
  requestId: string;
  openclawSessionKey: string | null;
  openclawRunId: string | null;
  eventId: string;
  rootExecutionId: string | null;
  traceOrphan: boolean;
}): string | null {
  const payloadTraceId =
    params.payload && typeof params.payload.traceId === "string" ? params.payload.traceId.trim() : "";
  const inputTraceId = input.traceId?.trim() || "";
  if (inputTraceId) return inputTraceId;
  if (payloadTraceId) return payloadTraceId;
  if (params.traceOrphan) return null;
  if (params.rootExecutionId) return params.rootExecutionId;
  if (params.openclawRunId) return params.openclawRunId;
  if (input.correlationId?.trim()) return input.correlationId.trim();
  if (params.openclawSessionKey && params.requestId) {
    return `${params.openclawSessionKey}:${params.requestId}`;
  }
  if (params.requestId) return params.requestId;
  if (params.openclawSessionKey) return `session:${params.openclawSessionKey}`;
  return params.eventId;
}

function resolveSpanId(
  input: NormalizeTelemetryInput,
  payload: PayloadMap,
  eventId: string,
  traceId: string | null,
): string | null {
  const payloadSpanId = payload && typeof payload.spanId === "string" ? payload.spanId.trim() : "";
  const inputSpanId = input.spanId?.trim() || "";
  if (inputSpanId) return inputSpanId;
  if (payloadSpanId) return payloadSpanId;
  if (!traceId) return null;
  return eventId;
}

function isTraceOrphan(payload: PayloadMap): boolean {
  return payload?.__traceOrphan === true;
}

function resolveErrorClass(input: NormalizeTelemetryInput, payload: PayloadMap): string | null {
  if (input.errorClass?.trim()) return input.errorClass.trim();
  if (typeof payload?.errorClass === "string" && payload.errorClass.trim()) return payload.errorClass.trim();
  if (typeof payload?.error === "string" && payload.error.trim()) return "runtime_error";
  return null;
}

function resolveErrorCode(input: NormalizeTelemetryInput, payload: PayloadMap): string | null {
  const value =
    input.errorCode ||
    (typeof payload?.errorCode === "string" ? payload.errorCode : undefined) ||
    (typeof payload?.code === "string" ? payload.code : undefined);
  return value?.trim() || null;
}

function resolveToolExitCode(input: NormalizeTelemetryInput, payload: PayloadMap): number | null {
  return toInt(input.toolExitCode) || toInt(payload?.exitCode) || null;
}

function resolveSchemaVersion(input: NormalizeTelemetryInput): number {
  const raw = toInt(input.schemaVersion);
  return raw && raw > 0 ? raw : 2;
}

/**
 * Normalizes raw telemetry input into a canonical persistence envelope.
 *
 * Responsibilities include:
 * - stable identity/trace/span derivation
 * - payload redaction/hash metadata
 * - legacy field compatibility normalization
 * - observable extraction payload prep
 */
export function normalizeTelemetryEvent(input: NormalizeTelemetryInput): NormalizedTelemetryEnvelope {
  const payload = asPayloadRecord(input.payload);
  const { payloadRedacted, payloadHash, payloadBytes } = redactPayload(input.payload);
  const payloadRaw =
    input.payload === null || input.payload === undefined
      ? Prisma.JsonNull
      : (input.payload as Prisma.InputJsonValue);
  const detectionPayload =
    input.payload === null || input.payload === undefined
      ? ({} as Prisma.InputJsonValue)
      : (input.payload as Prisma.InputJsonValue);
  const traceOrphan = Boolean(input.traceOrphan) || isTraceOrphan(payload);
  const outcome = resolveOutcome(input, payload);
  const eventId = input.eventId?.trim() || crypto.randomUUID();
  const openclawCtx = resolveOpenClawContext(input, payload);
  const rootMessageId = resolveRootMessageId(input, payload);
  const rootExecutionId = resolveRootExecutionId(input, payload, rootMessageId, openclawCtx);
  const openclawSessionKey = openclawCtx.sessionKey || openclawCtx.sessionId || openclawCtx.runId || null;
  const openclawSessionId = openclawCtx.sessionId || openclawCtx.sessionKey || null;
  const requestId =
    resolveRequestId(input, payload) ||
    input.correlationId?.trim() ||
    input.traceId?.trim() ||
    openclawCtx.runId ||
    eventId;
  const traceId = resolveTraceId(input, {
    payload,
    requestId,
    openclawSessionKey,
    openclawRunId: openclawCtx.runId,
    eventId,
    rootExecutionId,
    traceOrphan,
  });
  const spanId = resolveSpanId(input, payload, eventId, traceId);
  const parentSpanId = resolveParentSpanId(input, payload);

  const row: Prisma.TelemetryEventCreateManyInput = {
    eventId,
    ts: normalizeTimestamp(input.ts),
    severity: String(input.severity || "info").trim() || "info",
    category: String(input.category || "diagnostic").trim() || "diagnostic",
    action: String(input.action || "event").trim() || "event",
    projectId: input.projectId?.trim() || null,
    agentInstanceId: input.agentInstanceId?.trim() || null,
    agentName: resolveAgentName(input, payload),
    requestId,
    correlationId: input.correlationId?.trim() || traceId || null,
    rootExecutionId,
    rootMessageId,
    traceId,
    spanId,
    parentSpanId,
    outcome,
    outcomeReason: resolveOutcomeReason(input, payload),
    policyRuleId: resolvePolicyRuleId(input, payload),
    policyDecisionId: resolvePolicyDecisionId(input, payload),
    result: input.result?.trim() || toLegacyResult(outcome),
    durationMs: toInt(input.durationMs),
    latencyMs: resolveLatencyMs(input, payload),
    errorClass: resolveErrorClass(input, payload),
    errorCode: resolveErrorCode(input, payload),
    toolExitCode: resolveToolExitCode(input, payload),
    sourceIp: input.sourceIp?.trim() || null,
    sourceHost: input.sourceHost?.trim() || null,
    sourcePort: toInt(input.sourcePort),
    schemaVersion: resolveSchemaVersion(input),
    openclawAgentId: openclawCtx.agentId,
    openclawSessionKey,
    openclawSessionId,
    openclawRunId: openclawCtx.runId,
    openclawToolName: openclawCtx.toolName,
    openclawToolCallId: openclawCtx.toolCallId,
    openclawGatewayPort: openclawCtx.gatewayPort,
    payload: payloadRaw,
    payloadRedacted,
    payloadHash,
    payloadBytes,
  };

  const observables = extractObservables({
    sourceIp: row.sourceIp,
    iocType: row.iocType ?? null,
    iocValue: row.iocValue ?? null,
    payloadRedacted,
  });

  return {
    row,
    detectionPayload,
    observables,
  };
}
