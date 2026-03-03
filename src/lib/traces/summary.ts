/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/traces/summary.ts.
 */
import type { SerializedTrace, SerializedTraceSpan } from "@/lib/traces/query";
import type { ClassifiedTraceSpan, TracePhaseId } from "@/lib/traces/semantic";
import { getActionKey, getSpanPayloadRecord, getSpanPayloadValue } from "@/lib/traces/semantic";

export type TraceExecutionIssue = {
  id: string;
  kind: "tool_error" | "policy_block" | "run_error";
  label: string;
  description: string;
  spanId: string;
};

export type TraceToolUsage = {
  tool: string;
  count: number;
  called: string[];
};

export type TraceInputArtifact = {
  kind: "file" | "url" | "media";
  label: string;
  source: string;
  mimeType?: string;
  fileName?: string;
  filePath?: string;
  url?: string;
};

export type TraceRunSummary = {
  durationMs: number | null;
  finalOutcome: string;
  toolCallCount: number;
  toolResultCount: number;
  toolErrorCount: number;
  uniqueToolsUsed: number;
  retries: number;
  messagesExchanged: number;
  finalAssistantMessageLength?: number;
  contextHistoryCount?: number;
  promptLen?: number;
  provider?: string;
  model?: string;
  tokensIn?: number;
  tokensOut?: number;
  tokensTotal?: number;
  toolsUsed: TraceToolUsage[];
  inputArtifacts: TraceInputArtifact[];
  visitedUrls: string[];
  issues: TraceExecutionIssue[];
  phaseCounts: Record<TracePhaseId, number>;
};

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

function asNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string") {
    const parsed = Number(value.trim());
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}

function phaseCountSeed(): Record<TracePhaseId, number> {
  return {
    user_input: 0,
    model_preparation: 0,
    agent_execution: 0,
    assistant_response: 0,
    completion: 0,
    other: 0,
  };
}

function extractUrlsFromText(text: string): string[] {
  const out: string[] = [];
  const re = /https?:\/\/[^\s"'<>`]+/gi;
  let match = re.exec(text);
  while (match) {
    const raw = match[0]?.trim();
    if (raw) {
      const normalized = raw.replace(/[),.;]+$/g, "");
      if (normalized) out.push(normalized);
    }
    match = re.exec(text);
  }
  return out;
}

function addUrlsFromUnknown(value: unknown, out: Set<string>, depth = 0) {
  if (depth > 3 || value == null) return;
  if (typeof value === "string") {
    for (const url of extractUrlsFromText(value)) out.add(url);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value.slice(0, 20)) addUrlsFromUnknown(item, out, depth + 1);
    return;
  }
  const rec = asRecord(value);
  if (!rec) return;
  const keys = ["url", "href", "target", "command", "prompt", "promptPreview", "text", "content", "args", "params"];
  for (const key of keys) {
    if (!(key in rec)) continue;
    addUrlsFromUnknown(rec[key], out, depth + 1);
  }
}

function extractToolTarget(span: SerializedTraceSpan): string | undefined {
  const payload = getSpanPayloadRecord(span);
  const params = asRecord(payload?.params);
  return (
    asString(params?.url) ??
    asString(params?.domain) ??
    asString(params?.host) ??
    asString(params?.file_path) ??
    asString(params?.path) ??
    asString(params?.command) ??
    undefined
  );
}

function extractToolArgsPreview(span: SerializedTraceSpan): string | undefined {
  const payload = getSpanPayloadRecord(span);
  const params = asRecord(payload?.params);
  if (!params) return undefined;
  const command = asString(params.command);
  if (command) return command.slice(0, 220);
  try {
    return JSON.stringify(params).slice(0, 220);
  } catch {
    return undefined;
  }
}

function buildRetrySignature(span: SerializedTraceSpan): string | undefined {
  if (getActionKey(span) !== "tool.before_tool_call") return undefined;
  const tool = String(span.toolName || "").trim().toLowerCase();
  if (!tool) return undefined;
  const target = (extractToolTarget(span) || "-").trim().toLowerCase();
  return `${tool}|${target}`;
}

function resolveToolErrorDescription(span: SerializedTraceSpan): string {
  const payload = getSpanPayloadRecord(span);
  const msg =
    asString(span.outcomeReason) ??
    asString(payload?.error) ??
    asString(getSpanPayloadValue(span, ["status"])) ??
    "tool execution failed";
  return msg;
}

function normalizeArtifact(value: unknown, source: string): TraceInputArtifact | null {
  const rec = asRecord(value);
  if (!rec) return null;

  const filePath = asString(rec.filePath) ?? asString(rec.file_path) ?? asString(rec.path) ?? asString(rec.mediaPath);
  const url = asString(rec.url) ?? asString(rec.mediaUrl) ?? asString(rec.href);
  const fileName = asString(rec.fileName) ?? asString(rec.file_name) ?? asString(rec.filename) ?? asString(rec.name);
  const mimeType = asString(rec.mimeType) ?? asString(rec.mime_type) ?? asString(rec.mimetype) ?? asString(rec.contentType) ?? asString(rec.type);
  const label = asString(rec.label) ?? asString(rec.kind) ?? fileName ?? filePath ?? url ?? mimeType;

  if (!label && !filePath && !url && !mimeType) {
    return null;
  }

  const kind: TraceInputArtifact["kind"] = filePath ? "file" : (url ? "url" : "media");

  return {
    kind,
    label: label || kind,
    source,
    mimeType,
    fileName,
    filePath,
    url,
  };
}

function collectArtifactsFromSpan(span: SerializedTraceSpan, out: Map<string, TraceInputArtifact>) {
  const payload = getSpanPayloadRecord(span);
  if (!payload) return;

  const artifacts = payload.artifacts;
  if (Array.isArray(artifacts)) {
    for (const item of artifacts.slice(0, 24)) {
      const artifact = normalizeArtifact(item, `${getActionKey(span)}.artifacts`);
      if (!artifact) continue;
      const key = `${artifact.kind}|${artifact.filePath ?? ""}|${artifact.url ?? ""}|${artifact.fileName ?? ""}|${artifact.mimeType ?? ""}`;
      if (!out.has(key)) out.set(key, artifact);
    }
  }

  const promptPreview = asString(payload.promptPreview) ?? asString(payload.prompt);
  if (promptPreview) {
    const markerRe = /\[media attached:\s*([^\]]+?)\]/gi;
    let match = markerRe.exec(promptPreview);
    let count = 0;
    while (match && count < 12) {
      const marker = (match[1] || "").trim();
      if (marker) {
        const mimeMatch = marker.match(/\(([^()]+\/[^()]+)\)/);
        const mimeType = mimeMatch?.[1]?.trim();
        const artifact: TraceInputArtifact = {
          kind: "media",
          label: marker,
          source: `${getActionKey(span)}.promptPreview`,
          mimeType,
          fileName: marker,
        };
        const key = `${artifact.kind}|${artifact.fileName ?? ""}|${artifact.mimeType ?? ""}|${artifact.source}`;
        if (!out.has(key)) out.set(key, artifact);
      }
      match = markerRe.exec(promptPreview);
      count += 1;
    }
  }
}

/**
 * Builds a high-signal run summary from trace + classified span data.
 *
 * The summary powers narrative/overview surfaces (tools used, retries, artifacts,
 * execution outcome) while preserving links back to raw span evidence.
 */
export function buildTraceRunSummary(
  trace: SerializedTrace | null,
  spans: SerializedTraceSpan[],
  classified: ClassifiedTraceSpan[],
): TraceRunSummary {
  const durationFromSpans = spans.length > 1
    ? Math.max(0, spans[spans.length - 1].ts - spans[0].ts)
    : null;

  const phaseCounts = phaseCountSeed();
  for (const item of classified) {
    phaseCounts[item.phase] += 1;
  }

  const toolCalls = spans.filter((span) => getActionKey(span) === "tool.before_tool_call");
  const toolResults = spans.filter((span) => getActionKey(span) === "tool.after_tool_call");

  const toolUsageMap = new Map<string, { count: number; called: Set<string> }>();
  const visitedUrls = new Set<string>();

  for (const span of toolCalls) {
    const tool = String(span.toolName || "unknown").trim() || "unknown";
    const target = extractToolTarget(span);
    const argsPreview = extractToolArgsPreview(span);
    if (!toolUsageMap.has(tool)) {
      toolUsageMap.set(tool, { count: 0, called: new Set<string>() });
    }
    const usage = toolUsageMap.get(tool)!;
    usage.count += 1;
    if (target) usage.called.add(target);
    else if (argsPreview) usage.called.add(argsPreview);

    const payload = getSpanPayloadRecord(span);
    addUrlsFromUnknown(payload, visitedUrls);
    if (target) addUrlsFromUnknown(target, visitedUrls);
    if (argsPreview) addUrlsFromUnknown(argsPreview, visitedUrls);
  }

  const toolsUsed: TraceToolUsage[] = [...toolUsageMap.entries()]
    .map(([tool, usage]) => ({ tool, count: usage.count, called: [...usage.called].slice(0, 8) }))
    .sort((a, b) => b.count - a.count || a.tool.localeCompare(b.tool));

  const retrySignatureMap = new Map<string, number>();
  for (const span of toolCalls) {
    const sig = buildRetrySignature(span);
    if (!sig) continue;
    retrySignatureMap.set(sig, (retrySignatureMap.get(sig) ?? 0) + 1);
  }
  let retries = 0;
  for (const count of retrySignatureMap.values()) {
    if (count > 1) retries += count - 1;
  }

  const messagesExchanged = spans.filter((span) => {
    const action = getActionKey(span);
    if (action.startsWith("message.")) return true;
    if (action === "session.before_message_write") {
      const role = asString(getSpanPayloadValue(span, ["role"]))?.toLowerCase();
      return role === "user" || role === "assistant";
    }
    return false;
  }).length;

  let provider: string | undefined;
  let model: string | undefined;
  let tokensIn: number | undefined;
  let tokensOut: number | undefined;
  let tokensTotal: number | undefined;
  let contextHistoryCount: number | undefined;
  let promptLen: number | undefined;
  let finalAssistantMessageLength: number | undefined;

  const artifactMap = new Map<string, TraceInputArtifact>();

  for (const span of spans) {
    const action = getActionKey(span);

    if (action === "message.received" || action === "session.llm_input") {
      collectArtifactsFromSpan(span, artifactMap);
      const payload = getSpanPayloadRecord(span);
      addUrlsFromUnknown(payload, visitedUrls);
    }

    if (action === "session.llm_input") {
      provider = provider ?? asString(getSpanPayloadValue(span, ["provider"]));
      model = model ?? asString(getSpanPayloadValue(span, ["model"]));
      contextHistoryCount = contextHistoryCount ?? asNumber(getSpanPayloadValue(span, ["historyMessageCount", "history_count"]));
      promptLen = promptLen ?? asNumber(getSpanPayloadValue(span, ["promptLen", "prompt_len"]));
    }

    if (action === "session.llm_output") {
      provider = provider ?? asString(getSpanPayloadValue(span, ["provider"]));
      model = model ?? asString(getSpanPayloadValue(span, ["model"]));
      const usage = asRecord(getSpanPayloadValue(span, ["usage"]));
      if (usage) {
        tokensIn = tokensIn ?? asNumber(usage.input ?? usage.inputTokens);
        tokensOut = tokensOut ?? asNumber(usage.output ?? usage.outputTokens);
        tokensTotal = tokensTotal ?? asNumber(usage.total ?? usage.totalTokens);
      }
      const assistantTexts = getSpanPayloadValue(span, ["assistantTexts"]);
      if (Array.isArray(assistantTexts) && assistantTexts.length > 0) {
        const first = assistantTexts.find((entry) => typeof entry === "string");
        if (typeof first === "string") {
          finalAssistantMessageLength = first.length;
        }
      }
      if (finalAssistantMessageLength == null) {
        const fallback = asString(getSpanPayloadValue(span, ["text", "assistantText"]));
        if (fallback) finalAssistantMessageLength = fallback.length;
      }
    }
  }

  const inputArtifacts = [...artifactMap.values()].slice(0, 24);
  for (const artifact of inputArtifacts) {
    if (artifact.url) visitedUrls.add(artifact.url);
  }

  const issues: TraceExecutionIssue[] = [];
  for (const span of toolResults) {
    const failedByOutcome = String(span.outcome || "").toLowerCase() === "error";
    const failedByStatus = String(span.status || "").toLowerCase() === "error";
    const hasErrorMsg = Boolean(asString(getSpanPayloadValue(span, ["error"])));
    if (!failedByOutcome && !failedByStatus && !hasErrorMsg) continue;
    const toolLabel = String(span.toolName || "tool");
    issues.push({
      id: `issue:${span.spanId}`,
      kind: "tool_error",
      label: `${toolLabel} failed`,
      description: resolveToolErrorDescription(span),
      spanId: span.spanId,
    });
  }

  for (const span of spans) {
    const action = getActionKey(span);
    if (String(span.category || "").toLowerCase() !== "policy") continue;
    const outcome = String(span.outcome || span.status || "").toLowerCase();
    if (outcome !== "block" && outcome !== "blocked") continue;
    issues.push({
      id: `issue:${span.spanId}`,
      kind: "policy_block",
      label: "Policy blocked action",
      description: asString(span.outcomeReason) ?? asString(getSpanPayloadValue(span, ["reason"])) ?? action,
      spanId: span.spanId,
    });
  }

  const finalOutcome = trace?.status || (spans[spans.length - 1]?.status ?? "running");
  if (String(finalOutcome).toLowerCase() === "error") {
    const anchor = spans[spans.length - 1]?.spanId || spans[0]?.spanId || "";
    issues.push({
      id: `issue:run:${anchor}`,
      kind: "run_error",
      label: "Run completed with error",
      description: "The execution ended in an error state.",
      spanId: anchor,
    });
  }

  return {
    durationMs: trace?.durationMs ?? durationFromSpans,
    finalOutcome,
    toolCallCount: toolCalls.length,
    toolResultCount: toolResults.length,
    toolErrorCount: issues.filter((item) => item.kind === "tool_error").length,
    uniqueToolsUsed: toolsUsed.length,
    retries,
    messagesExchanged,
    finalAssistantMessageLength,
    contextHistoryCount,
    promptLen,
    provider,
    model,
    tokensIn,
    tokensOut,
    tokensTotal,
    toolsUsed,
    inputArtifacts,
    visitedUrls: [...visitedUrls].slice(0, 40),
    issues: issues.slice(0, 16),
    phaseCounts,
  };
}
