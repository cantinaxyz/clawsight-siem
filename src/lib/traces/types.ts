/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/traces/types.ts.
 */
export type TraceRunStatus = "running" | "completed" | "failed";

export type TraceArtifact = {
  kind: "file" | "url" | "media";
  label?: string;
  mimeType?: string;
  fileName?: string;
  filePath?: string;
  url?: string;
  source: string;
};

export type TraceSummary = {
  traceId: string;
  source: string;
  requestKey?: string;
  runStatus: TraceRunStatus;
  hasErrors: boolean;
  hasWarnings: boolean;
  hasPolicyBlocks: boolean;
  errorCount: number;
  warnCount: number;
  blockCount: number;
  startedAt: string;
  durationMs?: number;
  spansCount: number;
};

export type TraceEvent = {
  id: string;
  ts: string;
  kind: "message" | "tool" | "policy" | "session" | "internal";
  name: string;
  phase?: "user_input" | "model_prep" | "execution" | "assistant" | "completion";
  toolCallId?: string;
  spanId?: string;
  parentSpanId?: string;
  summary?: string;
  status?: "ok" | "warn" | "block" | "error";
  durationMs?: number;
  toolName?: string;
  targetUrl?: string;
  targetDomain?: string;
  argsPreview?: string;
  argsBytes?: number;
  resultCode?: string;
  triggerType?: string;
  messageProvider?: string;
  sessionKind?: string;
  triggerReason?: string;
  artifacts?: TraceArtifact[];
  payload?: unknown;
};

export type TraceDetail = {
  traceId: string;
  requestKey?: string;
  runStatus: TraceRunStatus;
  hasErrors: boolean;
  errorCount: number;
  warnCount: number;
  blockCount: number;
  startedAt: string;
  endedAt?: string;
  durationMs?: number;
  model?: string;
  tokensIn?: number;
  tokensOut?: number;
  contextHistoryCount?: number;
  promptBytes?: number;
  messagesCount?: number;
  toolCallsCount?: number;
  uniqueTools?: Array<{ name: string; count: number }>;
  triggerType?: string;
  messageProvider?: string;
  sessionKind?: string;
  triggerReason?: string;
  externalDomains?: Array<{ domain: string; count: number }>;
  visitedUrls?: Array<{ url: string; tool?: string }>;
  errorSummary?: Array<{ code: string; message: string; count: number; firstAt?: string }>;
  events: TraceEvent[];
};

export type TraceStep = {
  id: string;
  type: "user_input" | "model_prep" | "tool_call" | "policy" | "assistant_response" | "completion" | "internal";
  ts: string;
  title: string;
  summary?: string;
  status?: "ok" | "warn" | "block" | "error";
  durationMs?: number;
  toolName?: string;
  targetUrl?: string;
  targetDomain?: string;
  events: TraceEvent[];
  internalEvents?: TraceEvent[];
};

export type TraceHighlights = {
  uniqueTools: Array<{ name: string; count: number }>;
  externalDomains: Array<{ domain: string; count: number }>;
  errorSummary: Array<{ code: string; message: string; count: number; firstAt?: string }>;
};

export type TraceTab = "all" | "messages" | "tools" | "policy";
export type TraceMode = "narrative" | "technical" | "raw";
