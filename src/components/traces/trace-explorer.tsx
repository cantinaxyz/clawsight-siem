/**
 * @fileoverview ClawSight SIEM module: platform/src/components/traces/trace-explorer.tsx.
 */
"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  Bot,
  ChevronDown,
  ChevronRight,
  Cpu,
  GitBranch,
  Globe,
  ShieldCheck,
  Wrench,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { SerializedTrace, SerializedTraceSpan } from "@/lib/traces/query";
import { buildTelemetryDisplay } from "@/lib/telemetry-display";
import {
  classifyTraceSpan,
  extractToolCallId,
  getActionKey,
  getSpanPayloadRecord,
  getSpanPayloadValue,
  groupTraceSpansByPhase,
  type ClassifiedTraceSpan,
  type TracePhaseId,
} from "@/lib/traces/semantic";
import { buildTraceRunSummary } from "@/lib/traces/summary";
import { buildTraceNarrative } from "@/lib/traces/narrative";

type TraceFilters = {
  sourceType?: string;
  status?: string;
  search?: string;
};

type Props = {
  initialTraces: SerializedTrace[];
  initialTotal: number;
  initialSpans: SerializedTraceSpan[];
  initialSelectedTraceId?: string;
  filters: TraceFilters;
  limit: number;
};

type ViewMode = "narrative" | "technical" | "raw";

type ToolInvocation = {
  id: string;
  toolName: string;
  toolCallId?: string;
  status: "ok" | "error" | "unknown";
  durationMs?: number;
  target?: string;
  argsPreview?: string;
  error?: string;
  requestId?: string;
  startTs: number;
  spanIds: string[];
  events: ClassifiedTraceSpan[];
};

function formatTime(ts: number) {
  return new Date(ts).toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

function formatDuration(durationMs: number | null | undefined) {
  if (durationMs == null || !Number.isFinite(durationMs)) return "-";
  if (durationMs < 1000) return `${durationMs}ms`;
  const sec = durationMs / 1000;
  if (sec < 60) return `${sec.toFixed(1)}s`;
  const min = Math.floor(sec / 60);
  const rem = sec % 60;
  return `${min}m ${rem.toFixed(1)}s`;
}

function resolveStageIcon(stage: string) {
  const normalized = stage.toLowerCase();
  if (normalized.startsWith("tool.")) return Wrench;
  if (normalized.startsWith("policy.")) return ShieldCheck;
  if (normalized.startsWith("llm.") || normalized.startsWith("model.")) return Bot;
  if (normalized.startsWith("automation.") || normalized.startsWith("queue.")) return Globe;
  if (normalized.startsWith("gateway.")) return Cpu;
  if (normalized.startsWith("run.")) return GitBranch;
  return AlertTriangle;
}

function statusBadgeClass(value?: string | null) {
  const normalized = String(value || "").toLowerCase();
  if (normalized === "blocked" || normalized === "block") {
    return "border-destructive/40 bg-destructive/10 text-destructive";
  }
  if (normalized === "error") {
    return "border-destructive/40 bg-destructive/10 text-destructive";
  }
  if (normalized === "warn") {
    return "border-yellow-500/30 bg-yellow-500/10 text-yellow-300";
  }
  if (normalized === "completed") {
    return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
  }
  if (normalized === "running") {
    return "border-primary/35 bg-primary/10 text-primary";
  }
  return "border-border bg-secondary text-secondary-foreground";
}

function eventCardClass(status: string) {
  const normalized = status.toLowerCase();
  if (normalized === "error" || normalized === "block") return "border-destructive/35 bg-destructive/5";
  if (normalized === "warn") return "border-yellow-500/30 bg-yellow-500/5";
  if (normalized === "running") return "border-primary/30 bg-primary/5";
  return "border-border bg-card";
}

function toJsonText(value: unknown): string {
  if (value == null) return "null";
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
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

function truncate(value: string, max = 220): string {
  return value.length <= max ? value : `${value.slice(0, max)}...`;
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
  if (command) return truncate(command, 220);
  try {
    return truncate(JSON.stringify(params), 220);
  } catch {
    return undefined;
  }
}

function extractToolError(span: SerializedTraceSpan): string | undefined {
  return (
    asString(span.outcomeReason) ||
    asString(getSpanPayloadValue(span, ["error", "status"])) ||
    undefined
  );
}

function buildToolInvocations(items: ClassifiedTraceSpan[]): ToolInvocation[] {
  const sorted = [...items].sort((a, b) => a.span.ts - b.span.ts || a.span.id - b.span.id);
  const byId = new Map<string, ToolInvocation>();
  const openByTool = new Map<string, ToolInvocation>();

  function createInvocation(item: ClassifiedTraceSpan): ToolInvocation {
    const span = item.span;
    const toolName = String(span.toolName || "unknown").trim() || "unknown";
    const toolCallId = extractToolCallId(span);
    const id = toolCallId || `tool-${span.spanId}`;
    const inv: ToolInvocation = {
      id,
      toolName,
      toolCallId,
      status: "unknown",
      durationMs: typeof span.durationMs === "number" ? span.durationMs : undefined,
      target: extractToolTarget(span),
      argsPreview: extractToolArgsPreview(span),
      error: extractToolError(span),
      requestId: span.requestId || undefined,
      startTs: span.ts,
      spanIds: [span.spanId],
      events: [item],
    };
    byId.set(id, inv);
    if (toolCallId) byId.set(`call:${toolCallId}`, inv);
    openByTool.set(toolName, inv);
    return inv;
  }

  for (const item of sorted) {
    const span = item.span;
    const action = getActionKey(span);
    if (!action.startsWith("tool.")) continue;

    const toolName = String(span.toolName || "unknown").trim() || "unknown";
    const toolCallId = extractToolCallId(span);

    let inv: ToolInvocation | undefined;
    if (toolCallId) {
      inv = byId.get(toolCallId) || byId.get(`call:${toolCallId}`) || byId.get(`tool-${toolCallId}`);
    }
    if (!inv) {
      inv = openByTool.get(toolName);
    }

    if (!inv || action === "tool.before_tool_call") {
      inv = createInvocation(item);
    } else {
      inv.events.push(item);
      inv.spanIds.push(span.spanId);
      if (!inv.target) inv.target = extractToolTarget(span);
      if (!inv.argsPreview) inv.argsPreview = extractToolArgsPreview(span);
      if (!inv.requestId && span.requestId) inv.requestId = span.requestId;
      if (!inv.durationMs && typeof span.durationMs === "number") inv.durationMs = span.durationMs;
      const err = extractToolError(span);
      if (err) inv.error = err;
    }

    const failed =
      String(span.outcome || "").toLowerCase() === "error" ||
      String(span.status || "").toLowerCase() === "error" ||
      Boolean(extractToolError(span));

    if (failed) {
      inv.status = "error";
    } else if (action === "tool.after_tool_call" && inv.status === "unknown") {
      inv.status = "ok";
    }

    if (action === "tool.after_tool_call") {
      openByTool.delete(toolName);
    }
  }

  const unique = [...new Set([...byId.values()])];
  unique.sort((a, b) => a.startTs - b.startTs);
  return unique;
}

async function fetchTraceSpans(traceId: string, limit = 600): Promise<SerializedTraceSpan[]> {
  const res = await fetch(`/api/traces/${encodeURIComponent(traceId)}/spans?limit=${limit}`, {
    method: "GET",
    cache: "no-store",
  });
  if (!res.ok) return [];
  const data = (await res.json()) as { data?: SerializedTraceSpan[] };
  return Array.isArray(data.data) ? data.data : [];
}

export default function TraceExplorer({
  initialTraces,
  initialTotal,
  initialSpans,
  initialSelectedTraceId,
  filters,
  limit,
}: Props) {
  const [traces, setTraces] = useState(initialTraces);
  const [totalTraces, setTotalTraces] = useState(initialTotal);
  const [manualSelectedTraceId, setManualSelectedTraceId] = useState(initialSelectedTraceId || "");
  const [spans, setSpans] = useState(initialSpans);
  const [connected, setConnected] = useState(false);

  const [mode, setMode] = useState<ViewMode>("narrative");
  const [showMessages, setShowMessages] = useState(true);
  const [showTools, setShowTools] = useState(true);
  const [showPolicy, setShowPolicy] = useState(true);
  const [showInternal, setShowInternal] = useState(false);
  const [phaseExpandedByTrace, setPhaseExpandedByTrace] = useState<Record<string, Record<string, boolean>>>({});
  const [toolExpandedByTrace, setToolExpandedByTrace] = useState<Record<string, Record<string, boolean>>>({});

  const cursorRef = useRef<{ ts: number; traceId: string }>({
    ts: initialTraces[0]?.updatedAt ?? 0,
    traceId: initialTraces[0]?.traceId ?? "",
  });

  const selectedTraceId = useMemo(() => {
    if (manualSelectedTraceId && traces.some((trace) => trace.traceId === manualSelectedTraceId)) {
      return manualSelectedTraceId;
    }
    return traces[0]?.traceId || "";
  }, [manualSelectedTraceId, traces]);

  const selectedTrace = useMemo(
    () => traces.find((trace) => trace.traceId === selectedTraceId) || null,
    [selectedTraceId, traces],
  );

  const phaseExpanded = useMemo(
    () => (selectedTraceId ? phaseExpandedByTrace[selectedTraceId] ?? {} : {}),
    [phaseExpandedByTrace, selectedTraceId],
  );
  const toolExpanded = useMemo(
    () => (selectedTraceId ? toolExpandedByTrace[selectedTraceId] ?? {} : {}),
    [toolExpandedByTrace, selectedTraceId],
  );

  useEffect(() => {
    if (!selectedTraceId) return;
    void fetchTraceSpans(selectedTraceId).then((next) => {
      setSpans(next);
    });
  }, [selectedTraceId]);

  useEffect(() => {
    const params = new URLSearchParams();
    if (filters.sourceType) params.set("sourceType", filters.sourceType);
    if (filters.status) params.set("status", filters.status);
    if (filters.search) params.set("search", filters.search);
    params.set("cursorTs", String(cursorRef.current.ts));
    if (cursorRef.current.traceId) params.set("cursorTraceId", cursorRef.current.traceId);
    params.set("limit", String(Math.max(20, Math.min(limit, 120))));

    const source = new EventSource(`/api/traces/stream?${params.toString()}`);

    const onTrace = (event: MessageEvent<string>) => {
      try {
        const payload = JSON.parse(event.data) as SerializedTrace;
        cursorRef.current = { ts: payload.updatedAt, traceId: payload.traceId };
        setTraces((current) => {
          const existingIdx = current.findIndex((item) => item.traceId === payload.traceId);
          const next = [...current];
          if (existingIdx >= 0) {
            next[existingIdx] = payload;
          } else {
            next.unshift(payload);
            setTotalTraces((count) => count + 1);
          }
          next.sort((a, b) => b.lastEventTs - a.lastEventTs);
          if (next.length > limit) next.length = limit;
          return next;
        });
        if (payload.traceId === selectedTraceId) {
          void fetchTraceSpans(payload.traceId).then((rows) => {
            setSpans(rows);
          });
        }
      } catch {
        // ignore malformed payload
      }
    };

    source.addEventListener("trace", onTrace);
    source.onopen = () => setConnected(true);
    source.onerror = () => setConnected(false);

    return () => {
      source.removeEventListener("trace", onTrace);
      source.close();
    };
  }, [filters.search, filters.sourceType, filters.status, limit, selectedTraceId]);

  const classified = useMemo(() => spans.map(classifyTraceSpan), [spans]);

  const filtered = useMemo(() => {
    return classified.filter((item) => {
      if (!showInternal && item.signal === "internal") return false;
      if (!showMessages && item.kind === "message") return false;
      if (!showTools && item.kind === "tool_call") return false;
      if (!showPolicy && item.kind === "policy_check") return false;
      return true;
    });
  }, [classified, showInternal, showMessages, showTools, showPolicy]);

  const phaseGroups = useMemo(() => groupTraceSpansByPhase(filtered), [filtered]);

  const summary = useMemo(
    () => buildTraceRunSummary(selectedTrace, spans, classified),
    [selectedTrace, spans, classified],
  );

  const narrative = useMemo(() => buildTraceNarrative(summary), [summary]);

  const togglePhase = (phaseId: TracePhaseId) => {
    if (!selectedTraceId) return;
    setPhaseExpandedByTrace((current) => {
      const traceState = current[selectedTraceId] ?? {};
      return {
        ...current,
        [selectedTraceId]: {
          ...traceState,
          [phaseId]: !traceState[phaseId],
        },
      };
    });
  };

  const toggleTool = (toolId: string) => {
    if (!selectedTraceId) return;
    setToolExpandedByTrace((current) => {
      const traceState = current[selectedTraceId] ?? {};
      return {
        ...current,
        [selectedTraceId]: {
          ...traceState,
          [toolId]: !traceState[toolId],
        },
      };
    });
  };

  const renderSpanCard = (item: ClassifiedTraceSpan) => {
    const span = item.span;
    const Icon = resolveStageIcon(span.stage);
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

    return (
      <div id={`span-${span.spanId}`} key={span.id} className="relative flex items-start gap-3">
        <div className={cn("relative z-10 flex h-7 w-7 items-center justify-center rounded-full border", eventCardClass(span.status))}>
          <Icon className="h-3.5 w-3.5" />
        </div>
        <div className={cn("min-w-0 flex-1 rounded-lg border p-3", eventCardClass(span.status))}>
          <div className="mb-1 flex flex-wrap items-center justify-between gap-2">
            <div className="flex min-w-0 items-center gap-2">
              <Badge className={statusBadgeClass(span.status)}>{span.status}</Badge>
              <span className="truncate text-xs text-muted-foreground">{span.stage}</span>
              {item.signal === "internal" ? (
                <Badge className="border-border bg-secondary text-secondary-foreground">internal</Badge>
              ) : null}
            </div>
            <span className="font-mono text-xs text-muted-foreground">{formatTime(span.ts)}</span>
          </div>

          <p className="text-sm text-foreground">
            {span.category}.{span.action}
            {span.toolName ? ` • ${span.toolName}` : ""}
          </p>

          {display.summary ? (
            <p className="mt-2 line-clamp-2 text-xs text-foreground">{display.summary}</p>
          ) : null}

          <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
            {span.durationMs != null ? <span>{span.durationMs}ms</span> : null}
            {span.latencyMs != null ? <span>latency {span.latencyMs}ms</span> : null}
            {span.requestId ? <span className="font-mono">req:{span.requestId.slice(0, 12)}</span> : null}
            {span.runId ? <span className="font-mono">run:{span.runId.slice(0, 12)}</span> : null}
          </div>

          {display.artifacts.length > 0 ? (
            <div className="mt-2 flex flex-wrap gap-1">
              {display.artifacts.slice(0, 4).map((artifact, idx) => (
                <Badge key={`${span.id}:artifact:${idx}`} className="border-primary/35 bg-primary/10 text-primary">
                  {artifact.kind.toUpperCase()}: {artifact.fileName ?? artifact.filePath ?? artifact.url ?? artifact.label ?? artifact.mimeType ?? "artifact"}
                </Badge>
              ))}
            </div>
          ) : null}

          {display.fields.length > 0 ? (
            <div className="mt-2 grid grid-cols-1 gap-1 text-xs text-muted-foreground md:grid-cols-2">
              {display.fields.slice(0, 6).map((field) => (
                <div key={`${span.id}:${field.label}`} className="break-words whitespace-pre-wrap">
                  <span className="font-medium text-foreground">{field.label}:</span> {field.value}
                </div>
              ))}
            </div>
          ) : null}
        </div>
      </div>
    );
  };

  const renderToolInvocationCard = (inv: ToolInvocation) => {
    const expanded = toolExpanded[inv.id] ?? false;
    const primarySpanId = inv.spanIds[0] ?? inv.id;
    const statusClass =
      inv.status === "error"
        ? "border-destructive/40 bg-destructive/10 text-destructive"
        : inv.status === "ok"
          ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
          : "border-border bg-secondary text-secondary-foreground";

    return (
      <div id={`span-${primarySpanId}`} key={inv.id} className="rounded-lg border border-border bg-card p-3">
        {inv.spanIds.map((spanId) => (
          <span key={`anchor:${inv.id}:${spanId}`} id={`span-${spanId}`} className="sr-only" />
        ))}
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="min-w-0">
            <p className="truncate text-sm text-foreground">
              {inv.toolName}
              {inv.target ? ` → ${truncate(inv.target, 110)}` : ""}
            </p>
            <p className="text-xs text-muted-foreground">
              {inv.durationMs != null ? `${inv.durationMs}ms` : "duration unknown"}
              {inv.requestId ? ` • req:${inv.requestId.slice(0, 12)}` : ""}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Badge className={statusClass}>{inv.status}</Badge>
            <button
              type="button"
              onClick={() => toggleTool(inv.id)}
              className="rounded-md border border-border bg-secondary px-2 py-1 text-xs text-secondary-foreground"
            >
              {expanded ? "Hide details" : "Show details"}
            </button>
          </div>
        </div>

        {inv.error ? (
          <p className="mt-2 text-xs text-destructive">{truncate(inv.error, 220)}</p>
        ) : null}

        {expanded ? (
          <div className="mt-3 space-y-2 text-xs text-muted-foreground">
            {inv.argsPreview ? (
              <div>
                <span className="font-medium text-foreground">args:</span> {inv.argsPreview}
              </div>
            ) : null}
            <div>
              <span className="font-medium text-foreground">lifecycle events:</span>{" "}
              {inv.events.map((item) => `${item.span.category}.${item.span.action}`).join(", ")}
            </div>
          </div>
        ) : null}
      </div>
    );
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          Showing <span className="font-medium text-foreground">{traces.length}</span> / {totalTraces} traces
        </p>
        <Badge className={cn(connected ? "border-primary/35 bg-primary/10 text-primary" : "border-border bg-secondary text-muted-foreground")}>
          SSE {connected ? "Live" : "Reconnecting"}
        </Badge>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[22rem_minmax(0,1fr)]">
        <div className="space-y-2">
          {traces.length === 0 ? (
            <div className="rounded-lg border border-border bg-card p-4 text-sm text-muted-foreground">
              No traces yet.
            </div>
          ) : (
            traces.map((trace) => (
              <button
                key={trace.traceId}
                type="button"
                onClick={() => setManualSelectedTraceId(trace.traceId)}
                className={cn(
                  "w-full rounded-lg border p-3 text-left transition-colors",
                  selectedTraceId === trace.traceId
                    ? "border-primary/35 bg-primary/10"
                    : "border-border bg-card hover:bg-secondary",
                )}
              >
                <div className="mb-2 flex items-center justify-between gap-3">
                  <span className="truncate font-mono text-xs text-primary">{trace.traceId}</span>
                  <Badge className={statusBadgeClass(trace.status)}>{trace.status}</Badge>
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs text-muted-foreground">
                  <span>{trace.sourceType}</span>
                  <span className="text-right tabular-nums">{trace.spanCount} spans</span>
                  <span>{trace.firstAction || trace.firstCategory || "-"}</span>
                  <span className="text-right tabular-nums">{formatTime(trace.lastEventTs)}</span>
                </div>
              </button>
            ))
          )}
        </div>

        <div className="min-w-0 rounded-lg border border-border bg-card">
          {selectedTrace ? (
            <>
              <div className="border-b border-border p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="font-mono text-sm text-foreground">{selectedTrace.traceId}</p>
                    <p className="text-xs text-muted-foreground">
                      {selectedTrace.openclawAgentId || "agent:unknown"} / {selectedTrace.openclawSessionKey || "session:unknown"}
                    </p>
                  </div>
                  <Badge className={statusBadgeClass(selectedTrace.status)}>{selectedTrace.status}</Badge>
                </div>

                <div className="mt-4 rounded-lg border border-border bg-background p-3">
                  <p className="mb-2 text-xs font-medium text-foreground">Run Summary</p>
                  <div className="grid grid-cols-2 gap-3 text-xs md:grid-cols-4">
                    <div>
                      <p className="text-muted-foreground">Status</p>
                      <p className="font-mono">{summary.finalOutcome}</p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Duration</p>
                      <p className="font-mono">{formatDuration(summary.durationMs)}</p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Model</p>
                      <p className="font-mono">{summary.provider && summary.model ? `${summary.provider}/${summary.model}` : "-"}</p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Tool calls</p>
                      <p className="font-mono">{summary.toolCallCount}</p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Unique tools</p>
                      <p className="font-mono">{summary.uniqueToolsUsed}</p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Retries</p>
                      <p className="font-mono">{summary.retries}</p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Messages</p>
                      <p className="font-mono">{summary.messagesExchanged}</p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Final message len</p>
                      <p className="font-mono">{summary.finalAssistantMessageLength ?? "-"}</p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Context history</p>
                      <p className="font-mono">{summary.contextHistoryCount ?? "-"}</p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Prompt size</p>
                      <p className="font-mono">{summary.promptLen != null ? `${summary.promptLen}B` : "-"}</p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Tokens in/out</p>
                      <p className="font-mono">{summary.tokensIn != null || summary.tokensOut != null ? `${summary.tokensIn ?? "-"}/${summary.tokensOut ?? "-"}` : "-"}</p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Tool errors</p>
                      <p className="font-mono">{summary.toolErrorCount}</p>
                    </div>
                  </div>
                </div>

                {summary.toolsUsed.length > 0 ? (
                  <div className="mt-3 rounded-lg border border-border bg-background p-3">
                    <p className="mb-2 text-xs font-medium text-foreground">External Tools Used</p>
                    <div className="space-y-2">
                      {summary.toolsUsed.map((item) => (
                        <div key={`tool-usage:${item.tool}`} className="rounded-md border border-border bg-card p-2">
                          <p className="text-xs text-foreground">
                            <span className="font-medium">{item.tool}</span> ({item.count})
                          </p>
                          {item.called.length > 0 ? (
                            <p className="mt-1 text-xs text-muted-foreground">
                              called: {item.called.slice(0, 3).join(" • ")}
                              {item.called.length > 3 ? " • ..." : ""}
                            </p>
                          ) : null}
                        </div>
                      ))}
                    </div>
                  </div>
                ) : null}

                {summary.inputArtifacts.length > 0 ? (
                  <div className="mt-3 rounded-lg border border-border bg-background p-3">
                    <p className="mb-2 text-xs font-medium text-foreground">Input Documents / Media</p>
                    <div className="flex flex-wrap gap-2">
                      {summary.inputArtifacts.slice(0, 12).map((artifact, idx) => (
                        <Badge key={`artifact:${idx}`} className="border-primary/35 bg-primary/10 text-primary">
                          {artifact.kind.toUpperCase()}: {artifact.fileName ?? artifact.filePath ?? artifact.url ?? artifact.label}
                        </Badge>
                      ))}
                    </div>
                  </div>
                ) : null}

                {summary.visitedUrls.length > 0 ? (
                  <div className="mt-3 rounded-lg border border-border bg-background p-3">
                    <p className="mb-2 text-xs font-medium text-foreground">Visited URLs</p>
                    <div className="space-y-1 text-xs">
                      {summary.visitedUrls.slice(0, 12).map((url) => (
                        <a
                          key={`visited-url:${url}`}
                          href={url}
                          target="_blank"
                          rel="noreferrer noopener"
                          className="block truncate text-primary underline"
                        >
                          {url}
                        </a>
                      ))}
                    </div>
                  </div>
                ) : null}

                {summary.issues.length > 0 ? (
                  <div className="mt-3 rounded-lg border border-destructive/35 bg-destructive/5 p-3">
                    <p className="mb-2 text-xs font-medium text-destructive">Errors during execution</p>
                    <ul className="space-y-1 text-xs text-muted-foreground">
                      {summary.issues.map((issue) => (
                        <li key={issue.id}>
                          <a className="text-foreground underline" href={`#span-${issue.spanId}`}>
                            {issue.label}
                          </a>
                          : {truncate(issue.description, 180)}
                        </li>
                      ))}
                    </ul>
                  </div>
                ) : null}
              </div>

              <div className="border-b border-border p-4">
                <div className="flex flex-wrap items-center gap-2">
                  {(["narrative", "technical", "raw"] as ViewMode[]).map((candidate) => (
                    <button
                      key={candidate}
                      type="button"
                      onClick={() => setMode(candidate)}
                      className={cn(
                        "rounded-md border px-3 py-1.5 text-xs capitalize",
                        mode === candidate
                          ? "border-primary/40 bg-primary/10 text-primary"
                          : "border-border bg-secondary text-secondary-foreground",
                      )}
                    >
                      {candidate}
                    </button>
                  ))}
                </div>

                <div className="mt-3 flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setShowMessages((v) => !v)}
                    className={cn(
                      "rounded-md border px-2.5 py-1 text-xs",
                      showMessages ? "border-primary/40 bg-primary/10 text-primary" : "border-border bg-secondary text-muted-foreground",
                    )}
                  >
                    Messages
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowTools((v) => !v)}
                    className={cn(
                      "rounded-md border px-2.5 py-1 text-xs",
                      showTools ? "border-primary/40 bg-primary/10 text-primary" : "border-border bg-secondary text-muted-foreground",
                    )}
                  >
                    Tool Calls
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowPolicy((v) => !v)}
                    className={cn(
                      "rounded-md border px-2.5 py-1 text-xs",
                      showPolicy ? "border-primary/40 bg-primary/10 text-primary" : "border-border bg-secondary text-muted-foreground",
                    )}
                  >
                    Policy Checks
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowInternal((v) => !v)}
                    className={cn(
                      "rounded-md border px-2.5 py-1 text-xs",
                      showInternal ? "border-primary/40 bg-primary/10 text-primary" : "border-border bg-secondary text-muted-foreground",
                    )}
                  >
                    Show internal lifecycle events
                  </button>
                </div>
              </div>

              <div className="relative p-4">
                <div className="absolute bottom-4 left-[1.08rem] top-4 w-px bg-border" />

                {mode === "narrative" ? (
                  <div className="mb-4 rounded-lg border border-border bg-background p-3">
                    <p className="mb-2 text-xs font-medium text-foreground">Execution narrative</p>
                    <ul className="space-y-1 text-sm text-muted-foreground">
                      {narrative.map((line, idx) => (
                        <li key={`narrative:${idx}`}>• {line}</li>
                      ))}
                    </ul>
                  </div>
                ) : null}

                {mode === "raw" ? (
                  <div className="rounded-lg border border-border bg-background p-3">
                    <pre className="max-h-[60vh] overflow-auto text-xs text-muted-foreground">{toJsonText(
                      filtered.map((item) => ({
                        id: item.span.id,
                        ts: item.span.ts,
                        stage: item.span.stage,
                        category: item.span.category,
                        action: item.span.action,
                        status: item.span.status,
                        phase: item.phase,
                        signal: item.signal,
                        kind: item.kind,
                        payload: item.span.payload ?? item.span.payloadRedacted ?? item.span.payloadSummary,
                      })),
                    )}</pre>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {phaseGroups.map((group) => {
                      const isOpen = phaseExpanded[group.id] ?? false;

                      const isAgentExecution = group.id === "agent_execution";
                      const toolItems = isAgentExecution ? group.items.filter((item) => item.kind === "tool_call") : [];
                      const policyItems = isAgentExecution ? group.items.filter((item) => item.kind === "policy_check") : [];
                      const internalItems = isAgentExecution ? group.items.filter((item) => item.signal === "internal") : [];
                      const otherItems = isAgentExecution
                        ? group.items.filter((item) => item.kind !== "tool_call" && item.kind !== "policy_check" && item.signal !== "internal")
                        : group.items;

                      const toolInvocations = isAgentExecution ? buildToolInvocations(toolItems) : [];
                      const toolResultCount = isAgentExecution
                        ? toolItems.filter((item) => getActionKey(item.span) === "tool.after_tool_call").length
                        : 0;

                      return (
                        <div key={group.id} className="rounded-lg border border-border bg-background">
                          <button
                            type="button"
                            onClick={() => togglePhase(group.id)}
                            className="flex w-full items-center justify-between gap-3 px-3 py-2 text-left"
                          >
                            <div className="flex items-center gap-2">
                              {isOpen ? <ChevronDown className="h-4 w-4 text-muted-foreground" /> : <ChevronRight className="h-4 w-4 text-muted-foreground" />}
                              <span className="text-sm font-medium text-foreground">{group.label}</span>
                            </div>
                            <Badge className="border-border bg-secondary text-secondary-foreground">
                              {group.items.length} events
                            </Badge>
                          </button>

                          {isOpen ? (
                            <div className="space-y-3 border-t border-border p-3">
                              {isAgentExecution ? (
                                <>
                                  <div className="space-y-2">
                                    <p className="text-xs font-medium text-foreground">Tool Calls ({toolInvocations.length})</p>
                                    {toolInvocations.length > 0 ? toolInvocations.map((inv) => renderToolInvocationCard(inv)) : (
                                      <p className="text-xs text-muted-foreground">No tool calls.</p>
                                    )}
                                  </div>

                                  <div className="space-y-2">
                                    <p className="text-xs font-medium text-foreground">Tool Results ({toolResultCount})</p>
                                    <p className="text-xs text-muted-foreground">
                                      Tool lifecycle results are folded into each Tool Call card.
                                    </p>
                                  </div>

                                  <div className="space-y-2">
                                    <p className="text-xs font-medium text-foreground">Policy Checks ({policyItems.length})</p>
                                    {policyItems.length > 0 ? policyItems.map((item) => renderSpanCard(item)) : (
                                      <p className="text-xs text-muted-foreground">No policy checks.</p>
                                    )}
                                  </div>

                                  {otherItems.length > 0 ? (
                                    <div className="space-y-2">
                                      <p className="text-xs font-medium text-foreground">Execution Events ({otherItems.length})</p>
                                      {otherItems.map((item) => renderSpanCard(item))}
                                    </div>
                                  ) : null}

                                  {showInternal ? (
                                    <div className="space-y-2">
                                      <p className="text-xs font-medium text-foreground">Internal Lifecycle Events ({internalItems.length})</p>
                                      {internalItems.length > 0 ? internalItems.map((item) => renderSpanCard(item)) : (
                                        <p className="text-xs text-muted-foreground">No internal events.</p>
                                      )}
                                    </div>
                                  ) : null}
                                </>
                              ) : (
                                group.items.map((item) => renderSpanCard(item))
                              )}
                            </div>
                          ) : null}
                        </div>
                      );
                    })}

                    {phaseGroups.length === 0 ? (
                      <div className="rounded-lg border border-border bg-background p-4 text-sm text-muted-foreground">
                        No spans match current filters.
                      </div>
                    ) : null}
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="p-4 text-sm text-muted-foreground">Select a trace to view timeline.</div>
          )}
        </div>
      </div>
    </div>
  );
}
