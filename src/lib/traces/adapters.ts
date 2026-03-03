/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/traces/adapters.ts.
 */
import type { SerializedTrace, SerializedTraceSpan } from "@/lib/traces/query";
import { buildTelemetryDisplay } from "@/lib/telemetry-display";
import type {
  TraceArtifact,
  TraceDetail,
  TraceEvent,
  TraceRunStatus,
  TraceSummary,
} from "@/lib/traces/types";

function toIso(ts: number | null | undefined): string {
  if (!ts || !Number.isFinite(ts)) return new Date(0).toISOString();
  return new Date(ts).toISOString();
}

function normalizeRunStatus(input: {
  storedStatus?: string | null;
  endedAt: number | null;
  errorCount: number;
  blockCount: number;
}): TraceRunStatus {
  const normalized = String(input.storedStatus || "").trim().toLowerCase();
  if (input.endedAt != null) return "completed";
  if (normalized === "failed" || normalized === "error" || normalized === "blocked" || normalized === "block") {
    return "failed";
  }
  if (input.errorCount > 0 || input.blockCount > 0) return "failed";
  return "running";
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function asString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function asNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string") {
    const parsed = Number(value.trim());
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}

type ExecutionContextMeta = {
  triggerType?: string;
  messageProvider?: string;
  sessionKind?: string;
  triggerReason?: string;
};

function getExecutionContext(payload: Record<string, unknown> | null): ExecutionContextMeta {
  const execution =
    payload && typeof payload.execution === "object" && payload.execution && !Array.isArray(payload.execution)
      ? (payload.execution as Record<string, unknown>)
      : null;
  return {
    triggerType:
      asString(execution?.trigger) ||
      asString(execution?.triggerType) ||
      asString(payload?.trigger) ||
      undefined,
    messageProvider:
      asString(execution?.messageProvider) ||
      asString(execution?.provider) ||
      asString(payload?.channel) ||
      undefined,
    sessionKind:
      asString(execution?.sessionKind) ||
      asString(payload?.sessionKind) ||
      undefined,
    triggerReason:
      asString(execution?.reason) ||
      asString(payload?.reason) ||
      undefined,
  };
}

function getActionName(span: SerializedTraceSpan): string {
  return `${String(span.category || "").trim().toLowerCase()}.${String(span.action || "").trim().toLowerCase()}`;
}

function getPayloadRecord(span: SerializedTraceSpan): Record<string, unknown> | null {
  return asRecord(span.payload) || asRecord(span.payloadRedacted) || asRecord(span.payloadSummary);
}

function mapPhase(actionName: string, payload: Record<string, unknown> | null): TraceEvent["phase"] {
  if (actionName === "message.received") {
    return "user_input";
  }
  if (actionName === "message.sending" || actionName === "message.sent") {
    return "assistant";
  }
  if (actionName === "session.before_message_write") {
    const role = asString(payload?.role)?.toLowerCase();
    if (role === "assistant") return "assistant";
    if (role === "toolresult") return "execution";
    return "user_input";
  }
  if (
    actionName === "session.before_model_resolve" ||
    actionName === "session.before_prompt_build" ||
    actionName === "session.llm_input"
  ) {
    return "model_prep";
  }
  if (actionName === "session.llm_output") {
    return "assistant";
  }
  if (actionName === "session.agent_end") {
    return "completion";
  }
  if (actionName.startsWith("tool.")) {
    return "execution";
  }
  if (actionName.startsWith("policy.")) {
    return "execution";
  }
  return undefined;
}

function mapKind(
  span: SerializedTraceSpan,
  actionName: string,
  payload: Record<string, unknown> | null,
): TraceEvent["kind"] {
  const category = String(span.category || "").toLowerCase();
  if (category === "message") return "message";
  if (category === "tool") return "tool";
  if (category === "policy") return "policy";
  if (category === "agent") return "session";
  if (category === "session") {
    if (actionName === "session.before_message_write") {
      const role = asString(payload?.role)?.toLowerCase();
      if (role === "assistant" || role === "user") return "message";
      if (role === "toolresult") return "tool";
    }
    if (
      actionName === "session.before_agent_start" ||
      actionName === "session.before_message_write" ||
      actionName === "session.before_prompt_build" ||
      actionName === "session.before_model_resolve"
    ) {
      return "internal";
    }
    return "session";
  }
  return "internal";
}

function getToolCallId(span: SerializedTraceSpan, payload: Record<string, unknown> | null): string | undefined {
  return (
    asString(payload?.toolCallId) ||
    asString(payload?.tool_call_id) ||
    asString(payload?.callId) ||
    asString(payload?.call_id)
  );
}

function mapEventStatus(span: SerializedTraceSpan): TraceEvent["status"] {
  const rawStatus = String(span.status || "").trim().toLowerCase();
  const rawOutcome = String(span.outcome || "").trim().toLowerCase();

  if (
    rawStatus === "block" ||
    rawStatus === "blocked" ||
    rawStatus === "deny" ||
    rawStatus === "denied" ||
    rawOutcome === "block" ||
    rawOutcome === "blocked" ||
    rawOutcome === "deny" ||
    rawOutcome === "denied"
  ) {
    return "block";
  }

  if (
    rawStatus === "warn" ||
    rawStatus === "warning" ||
    rawOutcome === "warn" ||
    rawOutcome === "warning"
  ) {
    return "warn";
  }

  if (rawStatus === "error" || rawOutcome === "error") {
    return "error";
  }

  return "ok";
}

function parseDomain(url: string): string | undefined {
  try {
    return new URL(url).hostname || undefined;
  } catch {
    return undefined;
  }
}

function getToolTarget(payload: Record<string, unknown> | null): { url?: string; domain?: string } {
  const params = asRecord(payload?.params);
  const candidateUrl = asString(params?.url) || asString(params?.href);
  const candidateDomain = asString(params?.domain) || asString(params?.host);
  if (candidateUrl) {
    return { url: candidateUrl, domain: parseDomain(candidateUrl) };
  }
  if (candidateDomain) {
    return { domain: candidateDomain };
  }
  return {};
}

function getToolArgsPreview(payload: Record<string, unknown> | null): string | undefined {
  const params = asRecord(payload?.params);
  if (!params) return undefined;
  const command = asString(params.command);
  if (command) return command;
  const path = asString(params.path) || asString(params.file_path) || asString(params.filePath);
  if (path) return path;
  try {
    return JSON.stringify(params).slice(0, 240);
  } catch {
    return undefined;
  }
}

function buildEventDisplay(span: SerializedTraceSpan): { summary?: string; artifacts: TraceArtifact[] } {
  const display = buildTelemetryDisplay({
    category: span.category,
    action: span.action,
    stage: span.stage,
    payload: span.payload,
    payloadRedacted: span.payloadRedacted,
    payloadSummary: span.payloadSummary,
    toolName: span.toolName,
    outcomeReason: span.outcomeReason,
  });
  return {
    summary: display.summary || undefined,
    artifacts: display.artifacts || [],
  };
}

/**
 * Adapts a serialized trace row from persistence format to UI summary format.
 */
export function adaptTraceSummary(row: SerializedTrace): TraceSummary {
  const runStatus = normalizeRunStatus({
    storedStatus: row.status,
    endedAt: row.endedAt,
    errorCount: row.errorCount,
    blockCount: row.blockCount,
  });
  return {
    traceId: row.traceId,
    source: row.sourceType,
    requestKey: row.openclawSessionKey || row.openclawRunId || row.requestId || undefined,
    runStatus,
    hasErrors: row.errorCount > 0,
    hasWarnings: row.warnCount > 0,
    hasPolicyBlocks: row.blockCount > 0,
    errorCount: row.errorCount,
    warnCount: row.warnCount,
    blockCount: row.blockCount,
    startedAt: toIso(row.startedAt),
    durationMs: row.durationMs ?? undefined,
    spansCount: row.spanCount,
  };
}

function collectModelAndTokenFields(spans: SerializedTraceSpan[]) {
  let model: string | undefined;
  let provider: string | undefined;
  let tokensIn: number | undefined;
  let tokensOut: number | undefined;
  let contextHistoryCount: number | undefined;
  let promptBytes: number | undefined;

  for (const span of spans) {
    const action = getActionName(span);
    const payload = getPayloadRecord(span);
    if (action === "session.llm_input") {
      model = model || asString(payload?.model);
      provider = provider || asString(payload?.provider);
      contextHistoryCount = contextHistoryCount ?? asNumber(payload?.historyMessageCount);
      promptBytes = promptBytes ?? asNumber(payload?.promptLen);
    }
    if (action === "session.llm_output") {
      model = model || asString(payload?.model);
      provider = provider || asString(payload?.provider);
      const usage = asRecord(payload?.usage);
      tokensIn = tokensIn ?? asNumber(usage?.input ?? usage?.inputTokens);
      tokensOut = tokensOut ?? asNumber(usage?.output ?? usage?.outputTokens);
    }
  }

  const modelFull = provider && model ? `${provider}/${model}` : model || provider;

  return {
    model: modelFull,
    tokensIn,
    tokensOut,
    contextHistoryCount,
    promptBytes,
  };
}

/**
 * Adapts serialized spans into normalized `TraceEvent` records consumed by UI.
 */
export function adaptTraceEvents(spans: SerializedTraceSpan[]): TraceEvent[] {
  return spans.map((span) => {
    const actionName = getActionName(span);
    const payload = getPayloadRecord(span);
    const execution = getExecutionContext(payload);
    const display = buildEventDisplay(span);
    const toolTarget = getToolTarget(payload);
    const kind = mapKind(span, actionName, payload);

    const status = mapEventStatus(span);

    let argsBytes: number | undefined;
    const params = asRecord(payload?.params);
    if (params) {
      try {
        argsBytes = JSON.stringify(params).length;
      } catch {
        argsBytes = undefined;
      }
    }

    return {
      id: String(span.id),
      ts: toIso(span.ts),
      kind,
      name: actionName,
      phase: mapPhase(actionName, payload),
      toolCallId: getToolCallId(span, payload),
      spanId: span.spanId || undefined,
      parentSpanId: span.parentSpanId || undefined,
      summary: display.summary,
      status,
      durationMs: span.durationMs ?? undefined,
      toolName: span.toolName || undefined,
      targetUrl: toolTarget.url,
      targetDomain: toolTarget.domain,
      argsPreview: getToolArgsPreview(payload),
      argsBytes,
      resultCode:
        asString(payload?.status) ||
        asString(payload?.code) ||
        asString(payload?.errorCode) ||
        (span.errorCode || undefined),
      triggerType: execution.triggerType,
      messageProvider: execution.messageProvider,
      sessionKind: execution.sessionKind,
      triggerReason: execution.triggerReason,
      artifacts: display.artifacts,
      payload: span.payload ?? span.payloadRedacted ?? span.payloadSummary,
    };
  });
}

/**
 * Builds a full `TraceDetail` projection from trace + span records.
 */
export function adaptTraceDetail(trace: SerializedTrace, spans: SerializedTraceSpan[]): TraceDetail {
  const events = adaptTraceEvents(spans);
  const modelFields = collectModelAndTokenFields(spans);
  const toolCallsCount = events.filter((event) => event.name === "tool.before_tool_call").length;
  const messagesCount = events.filter((event) => event.kind === "message").length;
  const triggerEvent =
    events.find((event) => event.triggerType && event.triggerType !== "run") ||
    events.find((event) => event.triggerType) ||
    events.find((event) => event.messageProvider);
  const triggerType =
    triggerEvent?.triggerType ||
    (trace.sourceType && trace.sourceType !== "user" ? trace.sourceType : undefined);
  const messageProvider = triggerEvent?.messageProvider;
  const sessionKind = triggerEvent?.sessionKind;
  const triggerReason = triggerEvent?.triggerReason;
  const runStatus = normalizeRunStatus({
    storedStatus: trace.status,
    endedAt: trace.endedAt,
    errorCount: trace.errorCount,
    blockCount: trace.blockCount,
  });

  return {
    traceId: trace.traceId,
    requestKey: trace.openclawSessionKey || trace.openclawRunId || trace.requestId || undefined,
    runStatus,
    hasErrors: trace.errorCount > 0,
    errorCount: trace.errorCount,
    warnCount: trace.warnCount,
    blockCount: trace.blockCount,
    startedAt: toIso(trace.startedAt),
    endedAt: trace.endedAt ? toIso(trace.endedAt) : undefined,
    durationMs: trace.durationMs ?? undefined,
    model: modelFields.model,
    tokensIn: modelFields.tokensIn,
    tokensOut: modelFields.tokensOut,
    contextHistoryCount: modelFields.contextHistoryCount,
    promptBytes: modelFields.promptBytes,
    messagesCount,
    toolCallsCount,
    triggerType,
    messageProvider,
    sessionKind,
    triggerReason,
    events,
  };
}
