/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/traces/deriveSteps.ts.
 */
import type { TraceDetail, TraceEvent, TraceStep } from "@/lib/traces/types";

function toMs(ts: string): number {
  const value = Date.parse(ts);
  return Number.isFinite(value) ? value : 0;
}

function phaseToStepType(phase?: TraceEvent["phase"]): TraceStep["type"] | undefined {
  if (phase === "user_input") return "user_input";
  if (phase === "model_prep") return "model_prep";
  if (phase === "assistant") return "assistant_response";
  if (phase === "completion") return "completion";
  if (phase === "execution") return undefined;
  return undefined;
}

function pickStepStatus(events: TraceEvent[]): TraceStep["status"] {
  if (events.some((event) => event.status === "block")) return "block";
  if (events.some((event) => event.status === "error")) return "error";
  if (events.some((event) => event.status === "warn")) return "warn";
  return "ok";
}

function titleForType(type: TraceStep["type"]): string {
  if (type === "user_input") return "User Input";
  if (type === "model_prep") return "Model Preparation";
  if (type === "tool_call") return "Tool Call";
  if (type === "policy") return "Policy Check";
  if (type === "assistant_response") return "Assistant Response";
  if (type === "completion") return "Completion";
  return "Internal";
}

function buildToolStep(events: TraceEvent[], fallbackId: string): TraceStep {
  const sorted = [...events].sort((a, b) => toMs(a.ts) - toMs(b.ts));
  const first = sorted[0];
  const toolName = first?.toolName || "tool";
  const status = pickStepStatus(sorted);
  const durationMs = sorted.find((event) => typeof event.durationMs === "number")?.durationMs;
  const targetUrl = sorted.find((event) => event.targetUrl)?.targetUrl;
  const targetDomain = sorted.find((event) => event.targetDomain)?.targetDomain;
  const summary = sorted.find((event) => event.summary)?.summary;

  return {
    id: `tool-${first?.toolCallId || first?.spanId || fallbackId}`,
    type: "tool_call",
    ts: first?.ts || new Date(0).toISOString(),
    title: `${titleForType("tool_call")}: ${toolName}`,
    summary,
    status,
    durationMs,
    toolName,
    targetUrl,
    targetDomain,
    events: sorted,
  };
}

function buildSimpleStep(type: TraceStep["type"], events: TraceEvent[], index: number): TraceStep {
  const sorted = [...events].sort((a, b) => toMs(a.ts) - toMs(b.ts));
  const status = pickStepStatus(sorted);
  const summary = sorted.find((event) => event.summary)?.summary;
  const durationMs = sorted.reduce((acc, event) => acc + (event.durationMs || 0), 0) || undefined;

  return {
    id: `${type}-${index}`,
    type,
    ts: sorted[0]?.ts || new Date(0).toISOString(),
    title: titleForType(type),
    summary,
    status,
    durationMs,
    events: sorted,
  };
}

/**
 * Converts raw trace events into semantic timeline steps used by trace/execution UI.
 *
 * Primary transformation rules:
 * - collapse tool lifecycle events into single `tool_call` steps
 * - preserve policy events as standalone steps
 * - group non-tool events by phase (`user_input`, `model_prep`, etc.)
 * - attach internal lifecycle noise to nearest semantic step
 */
export function deriveSteps(detail: TraceDetail): TraceStep[] {
  const events = [...detail.events].sort((a, b) => toMs(a.ts) - toMs(b.ts));
  const consumed = new Set<string>();
  const steps: TraceStep[] = [];

  // 1) Group tool lifecycle into semantic tool_call steps
  const toolGroups = new Map<string, TraceEvent[]>();
  for (const event of events) {
    if (event.kind !== "tool") continue;
    const key = event.toolCallId || event.spanId || event.id;
    if (!toolGroups.has(key)) {
      toolGroups.set(key, []);
    }
    toolGroups.get(key)?.push(event);
  }

  // 2) Build timeline preserving chronology
  let i = 0;
  while (i < events.length) {
    const event = events[i];
    if (consumed.has(event.id)) {
      i += 1;
      continue;
    }

    if (event.kind === "tool") {
      const key = event.toolCallId || event.spanId || event.id;
      const grouped = toolGroups.get(key) || [event];
      grouped.forEach((item) => consumed.add(item.id));
      steps.push(buildToolStep(grouped, String(i)));
      i += 1;
      continue;
    }

    if (event.kind === "policy") {
      consumed.add(event.id);
      steps.push({
        id: `policy-${event.id}`,
        type: "policy",
        ts: event.ts,
        title: titleForType("policy"),
        summary: event.summary,
        status: event.status,
        durationMs: event.durationMs,
        events: [event],
      });
      i += 1;
      continue;
    }

    const mappedType = phaseToStepType(event.phase);
    if (!mappedType) {
      consumed.add(event.id);
      if (steps.length > 0) {
        const last = steps[steps.length - 1];
        const mergedInternal = [...(last.internalEvents || []), event];
        steps[steps.length - 1] = {
          ...last,
          internalEvents: mergedInternal,
        };
      } else {
        steps.push({
          id: `internal-${event.id}`,
          type: "internal",
          ts: event.ts,
          title: titleForType("internal"),
          summary: event.summary,
          status: event.status,
          durationMs: event.durationMs,
          events: [],
          internalEvents: [event],
        });
      }
      i += 1;
      continue;
    }

    const bucket: TraceEvent[] = [];
    let j = i;
    while (j < events.length) {
      const candidate = events[j];
      if (consumed.has(candidate.id)) {
        j += 1;
        continue;
      }
      if (candidate.kind === "tool" || candidate.kind === "policy") break;
      if (phaseToStepType(candidate.phase) !== mappedType) break;
      bucket.push(candidate);
      consumed.add(candidate.id);
      j += 1;
    }

    if (bucket.length > 0) {
      steps.push(buildSimpleStep(mappedType, bucket, steps.length));
      i = j;
      continue;
    }

    i += 1;
  }

  return steps.sort((a, b) => toMs(a.ts) - toMs(b.ts));
}
