/**
 * @fileoverview ClawSight SIEM module: platform/src/app/executions/page.tsx.
 */
"use client";

import Link from "next/link";
import { Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  Activity,
  AlertTriangle,
  ArrowLeftRight,
  ArrowUpDown,
  Bot,
  ChevronRight,
  Clock,
  ExternalLink,
  Globe,
  Hash,
  History,
  MessageSquare,
  Crosshair,
  ShieldAlert,
  Search,
  Wrench,
  X,
} from "lucide-react";
import AppShell from "@/components/app-shell";
import { ExecutionIntentPanel } from "@/components/execution-intent-panel";
import { OutcomeBadge, TriggerBadge } from "@/components/trigger-badge";
import { Input } from "@/components/ui/input";
import { fetchExecutions } from "@/lib/executions/api";
import type { Execution, ExecutionIntentSummary, ExecutionOutcome, TriggerType } from "@/lib/executions/types";
import { adaptTraceDetail } from "@/lib/traces/adapters";
import type { TraceDetail } from "@/lib/traces/types";
import { cn } from "@/lib/utils";

function formatDuration(ms?: number) {
  if (!ms) return "-";
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  if (ms < 3_600_000) return `${Math.round(ms / 60_000)}m`;
  return `${(ms / 3_600_000).toFixed(1)}h`;
}

function formatRelativeTime(iso: string) {
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return `${Math.round(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.round(diff / 3_600_000)}h ago`;
  return `${Math.round(diff / 86_400_000)}d ago`;
}

function shortHash(value: string): string {
  let hash = 0;
  for (let i = 0; i < value.length; i += 1) {
    hash = (hash * 31 + value.charCodeAt(i)) >>> 0;
  }
  return hash.toString(36).toUpperCase().padStart(6, "0").slice(-6);
}

function compactExecutionId(executionId: string): string {
  const parts = executionId.split(":").filter(Boolean);
  if (parts[0] === "msg") {
    const channel = (parts[1] || "msg").slice(0, 3).toUpperCase();
    const leaf = (parts[parts.length - 1] || "").replace(/[^a-zA-Z0-9]/g, "");
    return `${channel}-${(leaf || shortHash(executionId)).slice(-6).toUpperCase()}`;
  }
  if (parts[0] === "agent" && parts[parts.length - 1] === "bootstrap") {
    const scope = (parts[1] || "agent").replace(/[^a-zA-Z0-9]/g, "");
    return `BOOT-${(scope || shortHash(executionId)).slice(0, 6).toUpperCase()}`;
  }
  return `EXC-${shortHash(executionId)}`;
}

type ToolCallDetail = {
  id: string;
  toolName: string;
  status: "ok" | "warn" | "block" | "error";
  targetUrl?: string;
  targetDomain?: string;
  argsPreview?: string;
  resultCode?: string;
  durationMs?: number;
};

function mergeStatus(
  a: "ok" | "warn" | "block" | "error",
  b: "ok" | "warn" | "block" | "error",
): "ok" | "warn" | "block" | "error" {
  const rank = { ok: 0, warn: 1, block: 2, error: 3 } as const;
  return rank[b] > rank[a] ? b : a;
}

function deriveToolCallDetails(detail: TraceDetail): ToolCallDetail[] {
  const beforeCalls = detail.events.filter((event) => event.name === "tool.before_tool_call");
  const resultByToolCallId = new Map<
    string,
    { status: "ok" | "warn" | "block" | "error"; resultCode?: string; durationMs?: number }
  >();

  for (const event of detail.events) {
    if (event.name === "tool.before_tool_call") continue;
    if (!event.toolCallId) continue;
    const current = resultByToolCallId.get(event.toolCallId) || { status: "ok" as const };
    if (event.status) current.status = mergeStatus(current.status, event.status);
    current.resultCode = current.resultCode || event.resultCode;
    current.durationMs = current.durationMs ?? event.durationMs;
    resultByToolCallId.set(event.toolCallId, current);
  }

  return beforeCalls.map((event, index) => {
    const key = event.toolCallId || `tool-before-${index}`;
    const result = event.toolCallId ? resultByToolCallId.get(event.toolCallId) : undefined;
    return {
      id: key,
      toolName: event.toolName || "unknown",
      status: result?.status || event.status || "ok",
      targetUrl: event.targetUrl,
      targetDomain: event.targetDomain,
      argsPreview: event.argsPreview,
      resultCode: result?.resultCode || event.resultCode,
      durationMs: result?.durationMs ?? event.durationMs,
    };
  });
}

function IntentBadge({ summary }: { summary?: ExecutionIntentSummary }) {
  if (!summary) return <span className="text-[10px] text-muted-foreground">-</span>;
  const config = {
    normal: {
      label: "OK",
      bg: "bg-emerald-500/10",
      text: "text-emerald-400",
      border: "border-emerald-500/20",
    },
    elevated: {
      label: "Drift",
      bg: "bg-yellow-500/10",
      text: "text-yellow-400",
      border: "border-yellow-500/20",
    },
    high: {
      label: "High",
      bg: "bg-orange-500/10",
      text: "text-orange-400",
      border: "border-orange-500/20",
    },
    blocked: {
      label: "Blocked",
      bg: "bg-red-500/10",
      text: "text-red-400",
      border: "border-red-500/20",
    },
  }[summary.driftStatus];

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-full border px-1.5 py-0.5 text-[10px] font-medium",
        config.bg,
        config.text,
        config.border,
      )}
    >
      <Crosshair className="h-2.5 w-2.5" />
      {config.label}
    </span>
  );
}

const triggerTypes: TriggerType[] = ["user", "cron", "webhook", "retry", "chain", "system"];
const outcomes: ExecutionOutcome[] = ["completed", "error", "blocked", "running"];

async function fetchTraceDetail(traceId: string): Promise<TraceDetail | null> {
  const response = await fetch(`/api/traces/${encodeURIComponent(traceId)}?spanLimit=800`, {
    cache: "no-store",
  });
  const json = await response.json();
  if (!response.ok || !json?.trace || !Array.isArray(json?.spans)) {
    return null;
  }
  return adaptTraceDetail(json.trace, json.spans);
}

function ExecutionsPageContent() {
  const searchParams = useSearchParams();
  const focusedExecutionId = (searchParams.get("focusExecutionId") || "").trim();
  const searchFromQuery = (searchParams.get("search") || "").trim();

  const [executions, setExecutions] = useState<Execution[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState(searchFromQuery);
  const [filterTrigger, setFilterTrigger] = useState<TriggerType | "all">("all");
  const [filterOutcome, setFilterOutcome] = useState<ExecutionOutcome | "all">("all");
  const [filterAgent, setFilterAgent] = useState<string>("all");
  const [sortField, setSortField] = useState<"startedAt" | "durationMs" | "toolCalls">("startedAt");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [expandedSubTab, setExpandedSubTab] = useState<"details" | "intent">("details");
  const [traceDetails, setTraceDetails] = useState<Record<string, TraceDetail>>({});
  const [traceDetailLoading, setTraceDetailLoading] = useState<Record<string, boolean>>({});

  useEffect(() => {
    let cancelled = false;
    fetchExecutions({ limit: 250 })
      .then((data) => {
        if (!cancelled) {
          setExecutions(data);
          setLoading(false);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setExecutions([]);
          setLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    setSearch(searchFromQuery);
  }, [searchFromQuery]);

  const agentNames = useMemo(() => {
    const names = new Map<string, string>();
    executions.forEach((execution) => names.set(execution.agentKey, execution.agentName));
    return Array.from(names.entries());
  }, [executions]);

  const filtered = useMemo(() => {
    let result = executions;
    if (filterTrigger !== "all") result = result.filter((execution) => execution.triggerType === filterTrigger);
    if (filterOutcome !== "all") result = result.filter((execution) => execution.outcome === filterOutcome);
    if (filterAgent !== "all") result = result.filter((execution) => execution.agentKey === filterAgent);
    if (search) {
      const query = search.toLowerCase();
      result = result.filter(
        (execution) =>
          execution.executionId.toLowerCase().includes(query) ||
          execution.agentName.toLowerCase().includes(query) ||
          execution.triggerSource.toLowerCase().includes(query) ||
          (execution.triggerRef || "").toLowerCase().includes(query),
      );
    }

    return [...result].sort((a, b) => {
      if (focusedExecutionId) {
        const aFocused = a.executionId === focusedExecutionId;
        const bFocused = b.executionId === focusedExecutionId;
        if (aFocused !== bFocused) return aFocused ? -1 : 1;
      }

      const aValue =
        sortField === "startedAt"
          ? new Date(a.startedAt).getTime()
          : sortField === "durationMs"
            ? (a.durationMs ?? 0)
            : a.rollup.toolCalls;
      const bValue =
        sortField === "startedAt"
          ? new Date(b.startedAt).getTime()
          : sortField === "durationMs"
            ? (b.durationMs ?? 0)
            : b.rollup.toolCalls;
      return sortDir === "desc" ? bValue - aValue : aValue - bValue;
    });
  }, [executions, filterTrigger, filterOutcome, filterAgent, search, sortField, sortDir, focusedExecutionId]);

  function toggleSort(field: typeof sortField) {
    if (sortField === field) {
      setSortDir((value) => (value === "desc" ? "asc" : "desc"));
      return;
    }
    setSortField(field);
    setSortDir("desc");
  }

  async function handleExpand(execution: Execution) {
    if (expandedId === execution.executionId) {
      setExpandedId(null);
      return;
    }

    setExpandedId(execution.executionId);
    setExpandedSubTab("details");
    if (!traceDetails[execution.executionId] && !traceDetailLoading[execution.executionId]) {
      setTraceDetailLoading((current) => ({ ...current, [execution.executionId]: true }));
      const detail = await fetchTraceDetail(execution.executionId);
      setTraceDetailLoading((current) => ({ ...current, [execution.executionId]: false }));
      if (detail) {
        setTraceDetails((current) => ({ ...current, [execution.executionId]: detail }));
      }
    }
  }

  const hasActiveFilters =
    filterTrigger !== "all" || filterOutcome !== "all" || filterAgent !== "all" || search !== "";

  return (
    <AppShell
      activeNav="traces"
      title="Executions"
      subtitle="Browse all agent runs with trigger context and outcome"
    >
      <div className="flex flex-col gap-6">
        <div className="flex flex-col gap-3">
          <div className="flex items-center gap-3">
            <div className="relative max-w-sm flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search by ID, agent, trigger source..."
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                className="pl-9"
              />
            </div>

            <select
              value={filterAgent}
              onChange={(event) => setFilterAgent(event.target.value)}
              className="h-9 rounded-md border border-border bg-card px-3 text-sm text-foreground"
            >
              <option value="all">All agents</option>
              {agentNames.map(([key, label]) => (
                <option key={key} value={key}>
                  {label}
                </option>
              ))}
            </select>

            {hasActiveFilters ? (
              <button
                onClick={() => {
                  setFilterTrigger("all");
                  setFilterOutcome("all");
                  setFilterAgent("all");
                  setSearch("");
                }}
                className="flex items-center gap-1 rounded-md border border-border px-2.5 py-1.5 text-xs text-muted-foreground transition-colors hover:text-foreground"
              >
                <X className="h-3 w-3" />
                Clear filters
              </button>
            ) : null}
          </div>

          <div className="flex items-center gap-2">
            <span className="mr-1 text-xs text-muted-foreground">Trigger:</span>
            <button
              onClick={() => setFilterTrigger("all")}
              className={cn(
                "rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors",
                filterTrigger === "all"
                  ? "border-primary/30 bg-primary/10 text-primary"
                  : "border-border text-muted-foreground hover:text-foreground",
              )}
            >
              All
            </button>
            {triggerTypes.map((type) => (
              <button key={type} onClick={() => setFilterTrigger(filterTrigger === type ? "all" : type)}>
                <TriggerBadge
                  type={type}
                  size="sm"
                  className={cn(
                    "cursor-pointer transition-opacity",
                    filterTrigger !== "all" && filterTrigger !== type && "opacity-40",
                  )}
                />
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2">
            <span className="mr-1 text-xs text-muted-foreground">Outcome:</span>
            <button
              onClick={() => setFilterOutcome("all")}
              className={cn(
                "rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors",
                filterOutcome === "all"
                  ? "border-primary/30 bg-primary/10 text-primary"
                  : "border-border text-muted-foreground hover:text-foreground",
              )}
            >
              All
            </button>
            {outcomes.map((value) => (
              <button key={value} onClick={() => setFilterOutcome(filterOutcome === value ? "all" : value)}>
                <OutcomeBadge
                  outcome={value}
                  size="sm"
                  className={cn(
                    "cursor-pointer transition-opacity",
                    filterOutcome !== "all" && filterOutcome !== value && "opacity-40",
                  )}
                />
              </button>
            ))}
          </div>
        </div>

        {loading ? (
          <div className="flex flex-col gap-2">
            {Array.from({ length: 8 }).map((_, index) => (
              <div key={index} className="h-12 w-full animate-pulse rounded-lg border border-border bg-muted/40" />
            ))}
          </div>
        ) : (
          <div className="overflow-hidden rounded-xl border border-border bg-card">
            <div className="grid grid-cols-[130px_170px_1fr_110px_90px_100px_110px_90px_70px] gap-0 border-b border-border bg-muted/30 px-4 py-2.5 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              <span>Execution</span>
              <span>Agent</span>
              <span>Trigger</span>
              <span>Outcome</span>
              <span>Intent</span>
              <button
                onClick={() => toggleSort("startedAt")}
                className="flex items-center gap-1 transition-colors hover:text-foreground"
              >
                <Clock className="h-3 w-3" />
                Time
                {sortField === "startedAt" ? <ArrowUpDown className="h-3 w-3" /> : null}
              </button>
              <button
                onClick={() => toggleSort("durationMs")}
                className="flex items-center gap-1 transition-colors hover:text-foreground"
              >
                Duration
                {sortField === "durationMs" ? <ArrowUpDown className="h-3 w-3" /> : null}
              </button>
              <button
                onClick={() => toggleSort("toolCalls")}
                className="flex items-center gap-1 transition-colors hover:text-foreground"
              >
                <Wrench className="h-3 w-3" />
                Tools
                {sortField === "toolCalls" ? <ArrowUpDown className="h-3 w-3" /> : null}
              </button>
              <span />
            </div>

            {filtered.length === 0 ? (
              <div className="flex items-center justify-center py-16 text-sm text-muted-foreground">
                No executions match your filters
              </div>
            ) : (
              <div className="divide-y divide-border">
                {filtered.map((execution, index) => {
                  const isExpanded = expandedId === execution.executionId;
                  const detail = traceDetails[execution.executionId];
                  const detailLoading = traceDetailLoading[execution.executionId];
                  const orderedExecutionId = `EXEC-${index + 1}`;
                  const toolCallDetails = detail ? deriveToolCallDetails(detail) : [];

                  return (
                    <div key={execution.executionId}>
                      <button
                        onClick={() => handleExpand(execution)}
                        className={cn(
                          "grid w-full grid-cols-[130px_170px_1fr_110px_90px_100px_110px_90px_70px] gap-0 px-4 py-3 text-left text-sm transition-colors hover:bg-secondary/50",
                          isExpanded && "bg-secondary/30",
                        )}
                      >
                        <span className="font-mono text-xs tracking-wide text-primary" title={execution.executionId}>
                          {orderedExecutionId}
                        </span>
                        <span className="truncate text-xs text-foreground">{execution.agentName}</span>
                        <div className="flex items-center gap-2">
                          <TriggerBadge type={execution.triggerType} size="sm" />
                          <span className="truncate font-mono text-xs text-muted-foreground">
                            {execution.triggerSource}
                          </span>
                        </div>
                        <div className="min-w-0 overflow-hidden">
                          <OutcomeBadge
                            outcome={execution.outcome}
                            size="sm"
                            compact
                            className="max-w-full whitespace-nowrap"
                          />
                        </div>
                        <IntentBadge summary={execution.intentSummary} />
                        <span className="tabular-nums text-xs text-muted-foreground">
                          {formatRelativeTime(execution.startedAt)}
                        </span>
                        <span className="tabular-nums text-xs text-foreground">
                          {formatDuration(execution.durationMs)}
                        </span>
                        <span className="tabular-nums text-xs text-foreground">{execution.rollup.toolCalls}</span>
                        <div className="flex items-center justify-end gap-2">
                          <ChevronRight
                            className={cn(
                              "h-3.5 w-3.5 text-muted-foreground transition-transform",
                              isExpanded && "rotate-90",
                            )}
                          />
                        </div>
                      </button>

                      {isExpanded ? (
                        <div className="border-t border-border bg-muted/20">
                          <div className="flex items-center gap-0 border-b border-border px-4">
                            {(["details", "intent"] as const).map((tab) => (
                              <button
                                key={tab}
                                onClick={() => setExpandedSubTab(tab)}
                                className={cn(
                                  "border-b-2 px-3 py-2 text-xs font-medium capitalize transition-colors",
                                  expandedSubTab === tab
                                    ? "border-primary text-foreground"
                                    : "border-transparent text-muted-foreground hover:text-foreground",
                                )}
                              >
                                {tab === "intent" ? <Crosshair className="mr-1 inline h-3 w-3" /> : null}
                                {tab}
                              </button>
                            ))}
                          </div>

                          {expandedSubTab === "intent" ? (
                            <div className="p-4">
                              <ExecutionIntentPanel
                                executionId={execution.executionId}
                                rootExecutionId={execution.rootExecutionId || execution.executionId}
                              />
                            </div>
                          ) : (
                            <div className="px-4 py-4">
                              <div className="grid grid-cols-1 gap-4">
                                <div className="space-y-3 rounded-lg border border-border bg-card p-3">
                                  <div className="flex items-center justify-between">
                                    <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                                      Execution overview
                                    </h4>
                                    <Link
                                      href={`/executions/${encodeURIComponent(execution.executionId)}`}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
                                    >
                                      See more
                                      <ExternalLink className="h-3 w-3" />
                                    </Link>
                                  </div>

                                  {detailLoading ? (
                                    <div className="h-24 w-full animate-pulse rounded-md border border-border bg-muted/40" />
                                  ) : detail ? (
                                    <div className="space-y-4">
                                      <div className="flex flex-wrap gap-2 text-xs">
                                        <div className="min-w-[140px] rounded-md border border-border bg-muted/20 px-2 py-1.5">
                                          <span className="flex items-center gap-1 text-muted-foreground">
                                            <Hash className="h-3 w-3" />
                                            Execution ID
                                          </span>
                                          <p className="font-mono text-foreground" title={execution.executionId}>
                                            {compactExecutionId(execution.executionId)}
                                          </p>
                                        </div>
                                        <div className="min-w-[120px] rounded-md border border-border bg-muted/20 px-2 py-1.5">
                                          <span className="flex items-center gap-1 text-muted-foreground">
                                            <Activity className="h-3 w-3" />
                                            Run status
                                          </span>
                                          <p className="text-foreground">{detail.runStatus}</p>
                                        </div>
                                        <div className="min-w-[110px] rounded-md border border-border bg-muted/20 px-2 py-1.5">
                                          <span className="flex items-center gap-1 text-muted-foreground">
                                            <Clock className="h-3 w-3" />
                                            Duration
                                          </span>
                                          <p className="text-foreground">{formatDuration(detail.durationMs)}</p>
                                        </div>
                                        <div className="min-w-[180px] rounded-md border border-border bg-muted/20 px-2 py-1.5">
                                          <span className="flex items-center gap-1 text-muted-foreground">
                                            <Bot className="h-3 w-3" />
                                            Model
                                          </span>
                                          <p className="truncate text-foreground">{detail.model || "-"}</p>
                                        </div>
                                        <div className="min-w-[100px] rounded-md border border-border bg-muted/20 px-2 py-1.5">
                                          <span className="flex items-center gap-1 text-muted-foreground">
                                            <MessageSquare className="h-3 w-3" />
                                            Messages
                                          </span>
                                          <p className="text-foreground">{detail.messagesCount ?? 0}</p>
                                        </div>
                                        <div className="min-w-[100px] rounded-md border border-border bg-muted/20 px-2 py-1.5">
                                          <span className="flex items-center gap-1 text-muted-foreground">
                                            <Wrench className="h-3 w-3" />
                                            Tool calls
                                          </span>
                                          <p className="text-foreground">
                                            {detail.toolCallsCount ?? execution.rollup.toolCalls}
                                          </p>
                                        </div>
                                        <div className="min-w-[120px] rounded-md border border-border bg-muted/20 px-2 py-1.5">
                                          <span className="flex items-center gap-1 text-muted-foreground">
                                            <Globe className="h-3 w-3" />
                                            Domains
                                          </span>
                                          <p className="text-foreground">
                                            {detail.externalDomains?.length ?? execution.rollup.domainsTouched}
                                          </p>
                                        </div>
                                        <div className="min-w-[90px] rounded-md border border-border bg-muted/20 px-2 py-1.5">
                                          <span className="flex items-center gap-1 text-muted-foreground">
                                            <AlertTriangle className="h-3 w-3" />
                                            Errors
                                          </span>
                                          <p className="text-destructive">{detail.errorCount}</p>
                                        </div>
                                        <div className="min-w-[120px] rounded-md border border-border bg-muted/20 px-2 py-1.5">
                                          <span className="flex items-center gap-1 text-muted-foreground">
                                            <ShieldAlert className="h-3 w-3" />
                                            Policy blocks
                                          </span>
                                          <p className="text-amber-300">{detail.blockCount}</p>
                                        </div>
                                        <div className="min-w-[150px] rounded-md border border-border bg-muted/20 px-2 py-1.5">
                                          <span className="flex items-center gap-1 text-muted-foreground">
                                            <ArrowLeftRight className="h-3 w-3" />
                                            Tokens in/out
                                          </span>
                                          <p className="text-foreground">
                                            {(detail.tokensIn ?? 0).toLocaleString()} /{" "}
                                            {(detail.tokensOut ?? 0).toLocaleString()}
                                          </p>
                                        </div>
                                        <div className="min-w-[120px] rounded-md border border-border bg-muted/20 px-2 py-1.5">
                                          <span className="flex items-center gap-1 text-muted-foreground">
                                            <History className="h-3 w-3" />
                                            History count
                                          </span>
                                          <p className="text-foreground">{detail.contextHistoryCount ?? 0}</p>
                                        </div>
                                      </div>

                                      <div className="space-y-2">
                                        <div className="flex items-center justify-between">
                                          <h5 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                                            Tools called
                                          </h5>
                                          <span className="text-[11px] text-muted-foreground">
                                            {toolCallDetails.length}
                                          </span>
                                        </div>

                                        {toolCallDetails.length > 0 ? (
                                          <div className="space-y-2">
                                            {toolCallDetails.map((toolCall) => (
                                              <details
                                                key={toolCall.id}
                                                className="rounded-md border border-border bg-muted/20 p-2 text-xs"
                                              >
                                                <summary className="flex cursor-pointer list-none items-center justify-between gap-2">
                                                  <p className="font-mono text-foreground">{toolCall.toolName}</p>
                                                  <div className="flex items-center gap-2">
                                                    <span
                                                      className={cn(
                                                        "rounded px-1.5 py-0.5 text-[10px] uppercase tracking-wide",
                                                        toolCall.status === "error" &&
                                                          "bg-destructive/15 text-destructive",
                                                        toolCall.status === "block" &&
                                                          "bg-amber-400/15 text-amber-300",
                                                        toolCall.status === "warn" &&
                                                          "bg-yellow-400/15 text-yellow-300",
                                                        toolCall.status === "ok" &&
                                                          "bg-emerald-400/15 text-emerald-300",
                                                      )}
                                                    >
                                                      {toolCall.status}
                                                    </span>
                                                    <span className="text-muted-foreground">
                                                      {formatDuration(toolCall.durationMs)}
                                                    </span>
                                                  </div>
                                                </summary>
                                                <div className="mt-2 space-y-1">
                                                  {toolCall.targetUrl || toolCall.targetDomain ? (
                                                    <p
                                                      className="truncate font-mono text-muted-foreground"
                                                      title={toolCall.targetUrl || toolCall.targetDomain}
                                                    >
                                                      {toolCall.targetUrl || toolCall.targetDomain}
                                                    </p>
                                                  ) : null}
                                                  {toolCall.argsPreview ? (
                                                    <p className="line-clamp-2 font-mono text-muted-foreground">
                                                      {toolCall.argsPreview}
                                                    </p>
                                                  ) : null}
                                                  {toolCall.resultCode ? (
                                                    <p className="text-muted-foreground">
                                                      Result: <span className="font-mono">{toolCall.resultCode}</span>
                                                    </p>
                                                  ) : null}
                                                </div>
                                              </details>
                                            ))}
                                          </div>
                                        ) : (
                                          <p className="text-xs text-muted-foreground">
                                            No tool calls recorded for this execution.
                                          </p>
                                        )}
                                      </div>
                                    </div>
                                  ) : (
                                    <p className="text-xs text-muted-foreground">
                                      Unable to load execution overview for this run.
                                    </p>
                                  )}
                                </div>
                              </div>
                            </div>
                          )}
                        </div>
                      ) : null}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {!loading ? (
          <p className="text-xs text-muted-foreground">
            Showing {filtered.length} of {executions.length} executions
          </p>
        ) : null}
      </div>
    </AppShell>
  );
}


export default function ExecutionsPage() {
  return (
    <Suspense fallback={<AppShell activeNav="traces" title="Executions" subtitle="Browse all agent runs with trigger context and outcome"><div className="h-48 animate-pulse rounded-xl border border-border bg-muted/30" /></AppShell>}>
      <ExecutionsPageContent />
    </Suspense>
  );
}
