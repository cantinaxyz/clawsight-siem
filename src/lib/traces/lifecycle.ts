/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/traces/lifecycle.ts.
 */
type PayloadRecord = Record<string, unknown> | null;

export type TraceSourceType = "user" | "cron" | "hook" | "heartbeat" | "webhook" | "queue" | "system";
export type TraceSpanStatus = "info" | "warn" | "block" | "error" | "running" | "completed";

export type OpenClawPayloadContext = {
  sessionKey?: string;
  sessionId?: string;
  runId?: string;
  toolName?: string;
  toolCallId?: string;
};

function lower(value: unknown): string {
  return String(value || "").trim().toLowerCase();
}

function asRecord(payload: unknown): PayloadRecord {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return null;
  }
  return payload as Record<string, unknown>;
}

function asString(value: unknown): string | undefined {
  const raw = String(value || "").trim();
  return raw.length > 0 ? raw : undefined;
}

function summarizeArtifacts(value: unknown): Record<string, unknown>[] | undefined {
  if (!Array.isArray(value) || value.length === 0) {
    return undefined;
  }
  const out: Record<string, unknown>[] = [];
  for (const item of value.slice(0, 6)) {
    if (!item || typeof item !== "object" || Array.isArray(item)) continue;
    const rec = item as Record<string, unknown>;
    const row: Record<string, unknown> = {};
    const keys = ["kind", "label", "mimeType", "fileName", "filePath", "url", "source"];
    for (const key of keys) {
      const raw = rec[key];
      if (raw == null) continue;
      if (typeof raw === "string") {
        row[key] = raw.length > 180 ? `${raw.slice(0, 180)}...` : raw;
      } else {
        row[key] = raw;
      }
    }
    if (Object.keys(row).length > 0) {
      out.push(row);
    }
  }
  return out.length > 0 ? out : undefined;
}

function payloadType(payload: PayloadRecord): string {
  return lower(payload?.type);
}

export function extractOpenClawPayloadContext(payload: unknown): OpenClawPayloadContext {
  const rec = asRecord(payload);
  return {
    sessionKey: asString(rec?.sessionKey),
    sessionId: asString(rec?.sessionId),
    runId: asString(rec?.runId),
    toolName: asString(rec?.toolName),
    toolCallId: asString(rec?.toolCallId),
  };
}

export function resolveTraceSourceType(input: {
  category?: string | null;
  action?: string | null;
  sessionKey?: string | null;
  payload?: unknown;
}): TraceSourceType {
  const category = lower(input.category);
  const action = lower(input.action);
  const sessionKey = lower(input.sessionKey);
  const payload = asRecord(input.payload);
  const diagType = payloadType(payload);
  const execution = asRecord(payload?.execution);
  const executionTrigger = lower(execution?.trigger ?? execution?.triggerType);
  const executionProvider = lower(execution?.messageProvider ?? execution?.provider);

  if (executionTrigger === "heartbeat") {
    return "heartbeat";
  }
  if (executionTrigger === "cron") {
    return "cron";
  }
  if (executionTrigger === "hook" || executionTrigger === "webhook") {
    return "hook";
  }
  if (executionTrigger === "user_message") {
    return "user";
  }
  if (executionProvider === "heartbeat") {
    return "heartbeat";
  }
  if (executionProvider === "cron-event") {
    return "cron";
  }
  if (executionProvider.startsWith("hook")) {
    return "hook";
  }

  if (
    action.includes("webhook") ||
    diagType.startsWith("webhook.") ||
    (typeof payload?.channel === "string" && action === "received" && category === "message")
  ) {
    return "webhook";
  }
  if (
    action.includes("queue") ||
    diagType.startsWith("queue.") ||
    diagType.startsWith("message.queued") ||
    diagType.startsWith("message.processed")
  ) {
    return "queue";
  }
  if (sessionKey.startsWith("hook:") || sessionKey.startsWith("hook_") || sessionKey.startsWith("hook-")) {
    return "hook";
  }
  if (sessionKey.startsWith("cron:") || sessionKey.startsWith("cron_") || sessionKey.startsWith("cron-")) {
    return "cron";
  }
  if (category === "gateway" || category === "log" || category === "diagnostic" || category === "agent") {
    return "system";
  }
  return "user";
}

export function resolveTraceStage(input: {
  category?: string | null;
  action?: string | null;
  outcome?: string | null;
  payload?: unknown;
}): string {
  const category = lower(input.category);
  const action = lower(input.action);
  const outcome = lower(input.outcome);
  const payload = asRecord(input.payload);
  const diagType = payloadType(payload);

  if (category === "agent" && action === "bootstrap") return "agent.bootstrap";

  if (diagType) {
    if (diagType === "run.attempt") return "run.attempt";
    if (diagType === "model.usage") return "llm.usage";
    if (diagType.startsWith("webhook.")) return `automation.${diagType}`;
    if (diagType.startsWith("message.")) return `queue.${diagType}`;
    if (diagType.startsWith("queue.")) return `queue.${diagType}`;
    if (diagType === "tool.loop") return "tool.loop";
    return `diagnostic.${diagType}`;
  }

  if (category === "session" && action === "before_agent_start") return "run.start";
  if (category === "session" && action === "agent_end") return "run.end";
  if (category === "session" && action === "before_compaction") return "context.compaction.start";
  if (category === "session" && action === "after_compaction") return "context.compaction.end";
  if (category === "session" && action === "before_model_resolve") return "model.resolve";
  if (category === "session" && action === "before_prompt_build") return "prompt.build";
  if (category === "session" && action === "llm_input") return "llm.input";
  if (category === "session" && action === "llm_output") return "llm.output";
  if (category === "session" && action === "before_reset") return "session.reset";
  if (category === "session" && action === "before_message_write") return "session.message.write";
  if (category === "session" && action === "start") return "session.start";
  if (category === "session" && action === "end") return "session.end";
  if (category === "tool" && action === "before_tool_call") return "tool.call.start";
  if (category === "tool" && action === "after_tool_call") {
    return outcome === "error" ? "tool.call.error" : "tool.call.end";
  }
  if (category === "tool" && action === "tool_result_persist") return "tool.result.persist";
  if (category === "policy") return "policy.decision";
  if (category === "message" && action === "received") return "message.inbound";
  if (category === "message" && action === "sending") return "message.outbound.attempt";
  if (category === "message" && action === "sent") return "message.outbound.sent";
  if (category === "gateway" && action === "start") return "gateway.start";
  if (category === "gateway" && action === "stop") return "gateway.stop";
  if (category === "agent" && action === "bootstrap") return "agent.bootstrap";

  return `${category || "event"}.${action || "unknown"}`;
}

export function resolveTraceSpanStatus(input: {
  category?: string | null;
  action?: string | null;
  outcome?: string | null;
  severity?: string | null;
  errorClass?: string | null;
  errorCode?: string | null;
}): TraceSpanStatus {
  const outcome = lower(input.outcome);
  const severity = lower(input.severity);
  const action = lower(input.action);
  const category = lower(input.category);

  if (outcome === "block" || outcome === "blocked" || outcome === "deny") {
    return "block";
  }
  if (outcome === "error" || input.errorClass || input.errorCode || severity === "error") {
    return "error";
  }
  if (outcome === "warn" || severity === "warn" || severity === "warning") {
    return "warn";
  }
  if (category === "session" && action === "before_agent_start") {
    return "running";
  }
  if (category === "session" && action === "agent_end") {
    return "completed";
  }
  return "info";
}

export function summarizePayloadForTraceSpan(payload: unknown): Record<string, unknown> | null {
  const rec = asRecord(payload);
  if (!rec) return null;

  const pick = [
    "type",
    "toolName",
    "toolCallId",
    "channelId",
    "from",
    "to",
    "reason",
    "error",
    "result",
    "status",
    "sessionKey",
    "sessionId",
    "runId",
    "provider",
    "model",
    "agentName",
    "agentInstanceId",
    "hostName",
    "osPlatform",
    "osRelease",
    "osArch",
    "nodeVersion",
    "pluginVersion",
    "openclawVersion",
    "lane",
    "queueDepth",
    "outcome",
  ];

  const out: Record<string, unknown> = {};
  for (const key of pick) {
    if (!(key in rec)) continue;
    const value = rec[key];
    if (value == null) continue;
    if (typeof value === "string") {
      out[key] = value.length > 240 ? `${value.slice(0, 240)}...` : value;
      continue;
    }
    out[key] = value;
  }
  const execution = asRecord(rec.execution);
  if (execution) {
    const trigger = asString(execution.trigger) || asString(execution.triggerType);
    const messageProvider = asString(execution.messageProvider) || asString(execution.provider);
    const sessionKind = asString(execution.sessionKind);
    const reason = asString(execution.reason);
    if (trigger) out.executionTrigger = trigger;
    if (messageProvider) out.executionProvider = messageProvider;
    if (sessionKind) out.executionSessionKind = sessionKind;
    if (reason) out.executionReason = reason.length > 180 ? `${reason.slice(0, 180)}...` : reason;
  }
  const artifacts = summarizeArtifacts(rec.artifacts);
  if (artifacts) {
    out.artifacts = artifacts;
  }
  return Object.keys(out).length ? out : null;
}

export function resolveTraceStatusFromRollup(input: {
  errorCount: number;
  blockCount: number;
  warnCount: number;
  hasRunEnd: boolean;
}): "running" | "completed" | "failed" {
  if (input.hasRunEnd) return "completed";
  if (input.errorCount > 0 || input.blockCount > 0) return "failed";
  return "running";
}
