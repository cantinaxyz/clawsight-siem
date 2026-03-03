/**
 * @fileoverview ClawSight SIEM module: platform/src/components/execution-intent-panel.tsx.
 */
"use client";

import { Fragment, useEffect, useMemo, useState } from "react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Target,
  TrendingUp,
  ListChecks,
  Eye,
  X,
  AlertTriangle,
  Ban,
  Check,
  Pencil,
  Eraser,
} from "lucide-react";

type IntentExecution = {
  executionKey: string;
  rootExecutionId: string;
  agentInstanceId: string | null;
  managedAgentKey: string | null;
  taskBoundary: string | null;
  expectedScopes: string[];
  expectedDomains: string[];
  driftScore: number;
  status: string;
  extractionMethod: string | null;
  confidence: number | null;
  baselinePatched: boolean;
  baselineVersion: number;
  baselinePatchedAt: string | null;
  baselinePatchedBy: string | null;
  baselinePatchReason: string | null;
};

type IntentDecision = {
  id: number;
  phase: string;
  action: string;
  scoreDelta: number;
  driftScore: number;
  confidence: number | null;
  reason: string | null;
  toolName: string | null;
  targetDomain: string | null;
  signals?: string[] | null;
  details?: unknown;
  createdAt: string;
};

type IntentPayload = {
  execution: IntentExecution | null;
  decisions: IntentDecision[];
};

type DriftStatus = "normal" | "elevated" | "high" | "blocked";
type Verdict = "allow" | "warn" | "block" | "modify";

type DriftPoint = {
  timestamp: string;
  score: number;
  delta: number;
  toolName: string;
  reason: string;
};

function formatTime(iso: string): string {
  return new Date(iso).toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

function normalizeVerdict(input: string): Verdict {
  if (input === "warn" || input === "block" || input === "modify" || input === "allow") return input;
  return "allow";
}

function deriveDriftStatus(driftScore: number, blockCount: number): DriftStatus {
  if (blockCount > 0 || driftScore >= 70) return "blocked";
  if (driftScore >= 55) return "high";
  if (driftScore >= 30) return "elevated";
  return "normal";
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function valueToOneLine(value: unknown): string {
  try {
    if (typeof value === "string") return value;
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function pickToolParams(details: unknown): string | null {
  const rec = asRecord(details);
  if (!rec) return null;
  if ("params" in rec) return valueToOneLine(rec.params);
  if ("toolParams" in rec) return valueToOneLine(rec.toolParams);
  return null;
}

function pickSanitizedOutput(details: unknown): string | null {
  const rec = asRecord(details);
  if (!rec) return null;
  if ("sanitizedContent" in rec) return valueToOneLine(rec.sanitizedContent);
  if ("sanitizedOutput" in rec) return valueToOneLine(rec.sanitizedOutput);
  if ("content" in rec && typeof rec.content === "string" && String(rec.content).length <= 500) {
    return String(rec.content);
  }
  return null;
}

function pickContaminationFlags(decision: IntentDecision): string[] {
  const flags = Array.isArray(decision.signals)
    ? decision.signals.map((v) => String(v || "")).filter(Boolean)
    : [];
  const rec = asRecord(decision.details);
  if (rec && Array.isArray(rec.contaminationFlags)) {
    for (const item of rec.contaminationFlags) {
      const next = String(item || "").trim();
      if (next) flags.push(next);
    }
  }
  return Array.from(new Set(flags));
}

function DriftStatusPill({ status }: { status: DriftStatus }) {
  const config = {
    normal: { label: "Normal", bg: "bg-emerald-500/10", text: "text-emerald-400", border: "border-emerald-500/20" },
    elevated: { label: "Elevated", bg: "bg-yellow-500/10", text: "text-yellow-400", border: "border-yellow-500/20" },
    high: { label: "High", bg: "bg-orange-500/10", text: "text-orange-400", border: "border-orange-500/20" },
    blocked: { label: "Blocked", bg: "bg-red-500/10", text: "text-red-400", border: "border-red-500/20" },
  }[status];

  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[10px] font-medium", config.bg, config.text, config.border)}>
      {config.label}
    </span>
  );
}

function VerdictBadge({ verdict }: { verdict: Verdict }) {
  const config = {
    allow: { label: "Allow", icon: Check, className: "border-emerald-700 bg-emerald-600/20 text-emerald-300" },
    warn: { label: "Warn", icon: AlertTriangle, className: "border-yellow-700 bg-yellow-600/20 text-yellow-300" },
    block: { label: "Block", icon: Ban, className: "border-red-700 bg-red-600/20 text-red-300" },
    modify: { label: "Modify", icon: Pencil, className: "border-sky-700 bg-sky-600/20 text-sky-300" },
  }[verdict];
  const Icon = config.icon;
  return (
    <Badge className={cn("text-[10px]", config.className)}>
      <Icon className="mr-1 h-3 w-3" />
      {config.label}
    </Badge>
  );
}

function MiniSparkline({ points, warn, block }: { points: DriftPoint[]; warn: number; block: number }) {
  if (points.length === 0) return null;
  const maxScore = 100;
  const width = 280;
  const height = 48;
  const padX = 2;
  const padY = 4;
  const plotW = width - padX * 2;
  const plotH = height - padY * 2;

  const pathData = points
    .map((p, i) => {
      const x = padX + (i / Math.max(points.length - 1, 1)) * plotW;
      const y = padY + plotH - (p.score / maxScore) * plotH;
      return `${i === 0 ? "M" : "L"} ${x} ${y}`;
    })
    .join(" ");

  const warnY = padY + plotH - (warn / maxScore) * plotH;
  const blockY = padY + plotH - (block / maxScore) * plotH;

  return (
    <svg width={width} height={height} className="overflow-visible">
      <line x1={padX} y1={warnY} x2={width - padX} y2={warnY} stroke="currentColor" strokeDasharray="3 3" className="text-yellow-500/40" strokeWidth={1} />
      <line x1={padX} y1={blockY} x2={width - padX} y2={blockY} stroke="currentColor" strokeDasharray="3 3" className="text-red-500/40" strokeWidth={1} />
      <path d={pathData} fill="none" stroke="currentColor" strokeWidth={1.5} className="text-primary" />
      {points.map((p, i) => {
        const x = padX + (i / Math.max(points.length - 1, 1)) * plotW;
        const y = padY + plotH - (p.score / maxScore) * plotH;
        const color = p.score >= block ? "text-red-400" : p.score >= warn ? "text-yellow-400" : "text-primary";
        return <circle key={`${p.timestamp}-${i}`} cx={x} cy={y} r={2.5} fill="currentColor" className={color} />;
      })}
    </svg>
  );
}

export function ExecutionIntentPanel({
  executionId,
  rootExecutionId,
}: {
  executionId: string;
  rootExecutionId?: string;
}) {
  const [decisionFilter, setDecisionFilter] = useState<"all" | Verdict>("all");
  const [expandedDecision, setExpandedDecision] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [payload, setPayload] = useState<IntentPayload | null>(null);

  useEffect(() => {
    let cancelled = false;
    const root = (rootExecutionId || executionId || "").trim();
    Promise.resolve()
      .then(async () => {
        if (!cancelled) setLoading(true);
        if (!root) {
          return { execution: null, decisions: [] } as IntentPayload;
        }
        const response = await fetch(`/api/intent/executions/by-root/${encodeURIComponent(root)}`, {
          cache: "no-store",
        });
        const json = (await response.json()) as IntentPayload;
        if (!response.ok) throw new Error("intent_load_failed");
        return json;
      })
      .then((json) => {
        if (cancelled) return;
        setPayload(json);
      })
      .catch(() => {
        if (cancelled) return;
        setPayload({ execution: null, decisions: [] });
      })
      .finally(() => {
        if (cancelled) return;
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [executionId, rootExecutionId]);

  const execution = payload?.execution || null;
  const decisions = useMemo(() => payload?.decisions ?? [], [payload?.decisions]);

  const filteredDecisions = useMemo(() => {
    if (decisionFilter === "all") return decisions;
    return decisions.filter((d) => normalizeVerdict(d.action) === decisionFilter);
  }, [decisionFilter, decisions]);

  const driftPoints = useMemo<DriftPoint[]>(
    () =>
      decisions
        .filter((d) => d.phase !== "baseline")
        .map((d) => ({
          timestamp: d.createdAt,
          score: Number(d.driftScore || 0),
          delta: Number(d.scoreDelta || 0),
          toolName: d.toolName || d.phase,
          reason: d.reason || d.targetDomain || d.phase,
        })),
    [decisions],
  );

  const topDriftEvents = useMemo(
    () => [...driftPoints].sort((a, b) => b.delta - a.delta).slice(0, 3),
    [driftPoints],
  );

  const summary = useMemo(() => {
    if (!execution) return null;
    const blocks = decisions.filter((d) => normalizeVerdict(d.action) === "block").length;
    const warns = decisions.filter((d) => normalizeVerdict(d.action) === "warn").length;
    const sanitized = decisions.filter((d) => d.phase === "tool_output" && normalizeVerdict(d.action) === "modify").length;
    return {
      currentDriftScore: Number(execution.driftScore || 0),
      driftStatus: deriveDriftStatus(Number(execution.driftScore || 0), blocks),
      decisionsCount: decisions.length,
      warnsCount: warns,
      blocksCount: blocks,
      sanitizedCount: sanitized,
    };
  }, [execution, decisions]);

  if (loading) {
    return (
      <div className="flex h-48 items-center justify-center rounded-lg border border-border bg-card text-sm text-muted-foreground">
        Loading intent data...
      </div>
    );
  }

  if (!execution || !summary) {
    return (
      <div className="flex flex-col items-center justify-center py-10 text-muted-foreground">
        <Target className="mb-2 h-8 w-8" />
        <p className="text-sm">No intent data for this execution.</p>
        <p className="text-xs">Intent policy may be disabled or this execution has no baseline.</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-5">
      <div className="rounded-lg border border-border bg-card">
        <div className="flex items-center gap-2 border-b border-border px-4 py-3">
          <Target className="h-4 w-4 text-muted-foreground" />
          <h4 className="text-sm font-medium text-foreground">Execution Baseline</h4>
          <span className="ml-auto rounded bg-accent px-2 py-0.5 text-[10px] font-medium text-muted-foreground">
            {execution.extractionMethod === "heuristic"
              ? "Heuristic baseline"
              : `Model baseline (${execution.extractionMethod || "llm"})`}
          </span>
        </div>
        <div className="px-4 py-3">
          <div className="mb-3">
            <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Task boundary</span>
            <p className="mt-1 text-xs leading-relaxed text-foreground">
              {execution.taskBoundary || "No task boundary captured."}
            </p>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Expected scopes</span>
              <div className="mt-1 flex flex-wrap gap-1">
                {execution.expectedScopes.length > 0 ? (
                  execution.expectedScopes.map((scope) => (
                    <span key={scope} className="rounded bg-primary/10 px-1.5 py-0.5 font-mono text-[10px] text-primary">
                      {scope}
                    </span>
                  ))
                ) : (
                  <span className="text-[10px] text-muted-foreground">None</span>
                )}
              </div>
            </div>
            <div>
              <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Expected domains</span>
              <div className="mt-1 flex flex-wrap gap-1">
                {execution.expectedDomains.length > 0 ? (
                  execution.expectedDomains.map((domain) => (
                    <span key={domain} className="rounded bg-accent px-1.5 py-0.5 font-mono text-[10px] text-foreground">
                      {domain}
                    </span>
                  ))
                ) : (
                  <span className="text-[10px] text-muted-foreground">None</span>
                )}
              </div>
            </div>
          </div>
          <div className="mt-3 flex items-center gap-4 text-xs text-muted-foreground">
            {execution.baselinePatched ? (
              <span className="flex items-center gap-1 text-yellow-500">
                <AlertTriangle className="h-3 w-3" />
                Baseline patched (v{execution.baselineVersion})
              </span>
            ) : null}
            <span>
              Confidence:{" "}
              <span className="font-mono text-foreground">
                {execution.confidence != null ? `${execution.confidence}%` : "-"}
              </span>
            </span>
          </div>
        </div>
      </div>

      <div className="rounded-lg border border-border bg-card">
        <div className="flex items-center gap-2 border-b border-border px-4 py-3">
          <TrendingUp className="h-4 w-4 text-muted-foreground" />
          <h4 className="text-sm font-medium text-foreground">Drift Timeline</h4>
        </div>
        <div className="px-4 py-3">
          <div className="mb-3 flex items-center gap-4">
            <div>
              <span className="text-3xl font-bold tabular-nums text-foreground">{summary.currentDriftScore}</span>
              <span className="ml-1 text-xs text-muted-foreground">/100</span>
            </div>
            <DriftStatusPill status={summary.driftStatus} />
          </div>

          <MiniSparkline points={driftPoints} warn={30} block={70} />

          {topDriftEvents.length > 0 ? (
            <div className="mt-3">
              <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Largest drift events</span>
              <div className="mt-1.5 flex flex-col gap-1">
                {topDriftEvents.map((event, index) => (
                  <div key={`${event.timestamp}-${index}`} className="flex items-center gap-3 text-xs">
                    <span className="font-mono text-foreground">{event.toolName}</span>
                    <span className="font-mono text-red-400">+{event.delta}</span>
                    <span className="truncate text-muted-foreground">{event.reason}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : null}
        </div>
      </div>

      <div className="rounded-lg border border-border bg-card">
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <div className="flex items-center gap-2">
            <ListChecks className="h-4 w-4 text-muted-foreground" />
            <h4 className="text-sm font-medium text-foreground">Intent Decisions</h4>
            <span className="rounded bg-accent px-2 py-0.5 text-[10px] font-medium text-muted-foreground">
              {summary.decisionsCount}
            </span>
          </div>
          <div className="flex items-center gap-1.5">
            {(["all", "warn", "block", "modify"] as const).map((filter) => (
              <button
                key={filter}
                onClick={() => setDecisionFilter(filter)}
                className={cn(
                  "rounded-full border px-2 py-0.5 text-[10px] font-medium transition-colors",
                  decisionFilter === filter
                    ? "border-primary/30 bg-primary/10 text-primary"
                    : "border-border text-muted-foreground hover:text-foreground",
                )}
              >
                {filter === "all" ? "All" : filter.charAt(0).toUpperCase() + filter.slice(1)}
              </button>
            ))}
          </div>
        </div>

        {filteredDecisions.length === 0 ? (
          <div className="flex items-center justify-center py-8 text-xs text-muted-foreground">
            No decisions match this filter
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow className="border-border hover:bg-transparent">
                <TableHead className="w-[80px] text-[10px] text-muted-foreground">Time</TableHead>
                <TableHead className="w-[70px] text-[10px] text-muted-foreground">Stage</TableHead>
                <TableHead className="text-[10px] text-muted-foreground">Tool</TableHead>
                <TableHead className="w-[80px] text-[10px] text-muted-foreground">Decision</TableHead>
                <TableHead className="w-[55px] text-[10px] text-muted-foreground">Delta</TableHead>
                <TableHead className="w-[55px] text-[10px] text-muted-foreground">Drift</TableHead>
                <TableHead className="text-[10px] text-muted-foreground">Reason</TableHead>
                <TableHead className="w-[50px] text-[10px] text-muted-foreground" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredDecisions.map((decision) => {
                const verdict = normalizeVerdict(decision.action);
                const contaminationFlags = pickContaminationFlags(decision);
                return (
                  <Fragment key={decision.id}>
                    <TableRow key={decision.id} className="border-border">
                      <TableCell className="font-mono text-[11px] text-muted-foreground">
                        {formatTime(decision.createdAt)}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="text-[10px]">
                          {decision.phase}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-foreground">
                        {decision.toolName || decision.targetDomain || decision.phase}
                      </TableCell>
                      <TableCell>
                        <VerdictBadge verdict={verdict} />
                      </TableCell>
                      <TableCell className="font-mono text-xs text-red-400">
                        +{decision.scoreDelta}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-foreground">
                        {decision.driftScore}
                      </TableCell>
                      <TableCell className="max-w-[220px] truncate text-xs text-muted-foreground">
                        {decision.reason || "-"}
                      </TableCell>
                      <TableCell>
                        <button
                          onClick={() =>
                            setExpandedDecision((current) => (current === decision.id ? null : decision.id))
                          }
                          className="flex items-center gap-1 text-xs text-muted-foreground transition-colors hover:text-foreground"
                        >
                          {expandedDecision === decision.id ? (
                            <X className="h-3 w-3" />
                          ) : (
                            <Eye className="h-3 w-3" />
                          )}
                        </button>
                      </TableCell>
                    </TableRow>
                    {expandedDecision === decision.id ? (
                      <TableRow className="border-border bg-muted/20">
                        <TableCell colSpan={8}>
                          <div className="flex flex-col gap-2 py-2">
                            <div className="grid grid-cols-2 gap-4 text-xs">
                              <div>
                                <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Full reason</span>
                                <p className="mt-0.5 text-foreground">{decision.reason || "-"}</p>
                              </div>
                              {pickToolParams(decision.details) ? (
                                <div>
                                  <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
                                    Tool params (redacted)
                                  </span>
                                  <p className="mt-0.5 font-mono text-foreground">
                                    {pickToolParams(decision.details)}
                                  </p>
                                </div>
                              ) : null}
                            </div>

                            {pickSanitizedOutput(decision.details) ? (
                              <div className="text-xs">
                                <div className="flex items-center gap-1.5">
                                  <Eraser className="h-3 w-3 text-muted-foreground" />
                                  <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
                                    Sanitized output
                                  </span>
                                </div>
                                <div className="mt-1 rounded-md bg-secondary p-2 font-mono text-[11px] text-foreground">
                                  {pickSanitizedOutput(decision.details)}
                                </div>
                              </div>
                            ) : null}

                            {contaminationFlags.length > 0 ? (
                              <div className="flex items-center gap-2 text-xs">
                                <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
                                  Contamination:
                                </span>
                                {contaminationFlags.map((flag) => (
                                  <span
                                    key={`${decision.id}-${flag}`}
                                    className="rounded border border-red-500/20 bg-red-500/10 px-1.5 py-0.5 font-mono text-[10px] text-red-400"
                                  >
                                    {flag}
                                  </span>
                                ))}
                              </div>
                            ) : null}
                          </div>
                        </TableCell>
                      </TableRow>
                    ) : null}
                  </Fragment>
                );
              })}
            </TableBody>
          </Table>
        )}
      </div>
    </div>
  );
}
