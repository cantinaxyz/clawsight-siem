/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/traces/semantic.ts.
 */
import type { SerializedTraceSpan } from "@/lib/traces/query";

export type TracePhaseId =
  | "user_input"
  | "model_preparation"
  | "agent_execution"
  | "assistant_response"
  | "completion"
  | "other";

export type SignalLevel = "high" | "internal";

export type TraceEventKind =
  | "message"
  | "tool_call"
  | "policy_check"
  | "agent_action"
  | "payment"
  | "other";

export type ClassifiedTraceSpan = {
  span: SerializedTraceSpan;
  phase: TracePhaseId;
  signal: SignalLevel;
  kind: TraceEventKind;
};

export type TracePhaseGroup = {
  id: TracePhaseId;
  label: string;
  items: ClassifiedTraceSpan[];
};

const PHASE_LABELS: Record<TracePhaseId, string> = {
  user_input: "User Input",
  model_preparation: "Model Preparation",
  agent_execution: "Agent Execution",
  assistant_response: "Assistant Response",
  completion: "Completion",
  other: "Other",
};

const PHASE_ORDER: TracePhaseId[] = [
  "user_input",
  "model_preparation",
  "agent_execution",
  "assistant_response",
  "completion",
  "other",
];

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function asString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function payloadRecords(span: SerializedTraceSpan): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  const payloads = [span.payload, span.payloadRedacted, span.payloadSummary];
  for (const payload of payloads) {
    const rec = asRecord(payload);
    if (rec) out.push(rec);
  }
  return out;
}

export function getActionKey(span: SerializedTraceSpan): string {
  return `${String(span.category || "").toLowerCase()}.${String(span.action || "").toLowerCase()}`;
}

export function getSpanPayloadRecord(span: SerializedTraceSpan): Record<string, unknown> | null {
  const records = payloadRecords(span);
  return records[0] ?? null;
}

export function getSpanPayloadValue(span: SerializedTraceSpan, keys: string[]): unknown {
  const records = payloadRecords(span);
  for (const rec of records) {
    for (const key of keys) {
      if (!(key in rec)) continue;
      const value = rec[key];
      if (value != null) return value;
    }
  }
  return undefined;
}

export function getSpanRole(span: SerializedTraceSpan): string | undefined {
  const role = asString(getSpanPayloadValue(span, ["role"]));
  return role?.toLowerCase();
}

export function extractToolCallId(span: SerializedTraceSpan): string | undefined {
  const direct = asString(getSpanPayloadValue(span, ["toolCallId", "tool_call_id", "callId", "call_id"]));
  if (direct) return direct;
  const params = asRecord(getSpanPayloadValue(span, ["params"]));
  return (
    asString(params?.toolCallId) ||
    asString(params?.tool_call_id) ||
    undefined
  );
}

export function classifyTraceSpan(span: SerializedTraceSpan): ClassifiedTraceSpan {
  const action = getActionKey(span);
  const category = String(span.category || "").toLowerCase();
  const role = getSpanRole(span);

  if (action === "message.received") {
    return { span, phase: "user_input", signal: "high", kind: "message" };
  }

  if (action === "session.before_message_write") {
    if (role === "user") {
      return { span, phase: "user_input", signal: "internal", kind: "message" };
    }
    if (role === "toolresult") {
      return { span, phase: "agent_execution", signal: "internal", kind: "agent_action" };
    }
    if (role === "assistant") {
      return { span, phase: "assistant_response", signal: "internal", kind: "agent_action" };
    }
  }

  if (
    action === "session.before_model_resolve" ||
    action === "session.before_prompt_build" ||
    action === "session.llm_input"
  ) {
    return {
      span,
      phase: "model_preparation",
      signal: action === "session.llm_input" ? "high" : "internal",
      kind: "agent_action",
    };
  }

  if (action === "session.before_agent_start") {
    return {
      span,
      phase: "agent_execution",
      signal: "internal",
      kind: "agent_action",
    };
  }

  if (
    action === "tool.before_tool_call" ||
    action === "tool.after_tool_call" ||
    action === "tool.tool_result_persist"
  ) {
    return {
      span,
      phase: "agent_execution",
      signal: "high",
      kind: "tool_call",
    };
  }

  if (action === "session.llm_output") {
    return { span, phase: "assistant_response", signal: "high", kind: "agent_action" };
  }

  if (action === "session.agent_end") {
    return { span, phase: "completion", signal: "high", kind: "agent_action" };
  }

  if (category === "policy") {
    return { span, phase: "agent_execution", signal: "high", kind: "policy_check" };
  }

  if (category === "payment") {
    return { span, phase: "agent_execution", signal: "high", kind: "payment" };
  }

  if (category === "message") {
    return { span, phase: "assistant_response", signal: "high", kind: "message" };
  }

  return { span, phase: "other", signal: "internal", kind: "other" };
}

export function groupTraceSpansByPhase(items: ClassifiedTraceSpan[]): TracePhaseGroup[] {
  const grouped = new Map<TracePhaseId, ClassifiedTraceSpan[]>();
  for (const phase of PHASE_ORDER) {
    grouped.set(phase, []);
  }
  for (const item of items) {
    grouped.get(item.phase)?.push(item);
  }

  const out: TracePhaseGroup[] = [];
  for (const phase of PHASE_ORDER) {
    const rows = grouped.get(phase) ?? [];
    if (rows.length === 0) continue;
    out.push({ id: phase, label: PHASE_LABELS[phase], items: rows });
  }
  return out;
}

export function getPhaseLabel(phase: TracePhaseId): string {
  return PHASE_LABELS[phase];
}

export function getPhaseOrder(): TracePhaseId[] {
  return [...PHASE_ORDER];
}
