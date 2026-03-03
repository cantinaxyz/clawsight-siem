/**
 * @fileoverview ClawSight SIEM module: platform/src/app/agents/[agentKey]/_components/TimelineTab.tsx.
 */
"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { AlertTriangle, ChevronDown, ChevronRight, Globe, Wrench } from "lucide-react";
import { OutcomeBadge, TriggerBadge } from "@/components/trigger-badge";
import { cn } from "@/lib/utils";
import type { ExecutionOutcome, TriggerType } from "@/lib/executions/types";

type TimelineExecution = {
  executionId: string;
  triggerType: TriggerType;
  triggerSource: string;
  triggerRef?: string;
  outcome: ExecutionOutcome;
  startedAt: string;
  durationMs?: number;
  toolCalls: number;
  domainsTouched: number;
  errors: number;
  alertsRaised: number;
  parentExecutionId?: string;
};

type TimelineTabProps = {
  executions: TimelineExecution[];
};

const triggerTypes: TriggerType[] = ["user", "cron", "webhook", "retry", "chain", "system"];
const outcomeTypes: ExecutionOutcome[] = ["completed", "error", "blocked", "running"];

function formatDuration(ms?: number) {
  if (!ms) return "-";
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  if (ms < 3_600_000) return `${Math.round(ms / 60_000)}m`;
  return `${(ms / 3_600_000).toFixed(1)}h`;
}

function formatTime(iso: string) {
  return new Date(iso).toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

function getTimeGroup(iso: string): string {
  const date = new Date(iso);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffHours = diffMs / 3_600_000;

  if (diffHours < 1) return "Last hour";
  if (diffHours < 3) return "1-3 hours ago";
  if (diffHours < 6) return "3-6 hours ago";
  if (diffHours < 12) return "6-12 hours ago";
  if (diffHours < 24) return "12-24 hours ago";
  return "Older";
}

export default function TimelineTab({ executions }: TimelineTabProps) {
  const [filterTrigger, setFilterTrigger] = useState<TriggerType | "all">("all");
  const [filterOutcome, setFilterOutcome] = useState<ExecutionOutcome | "all">("all");
  const [errorsOnly, setErrorsOnly] = useState(false);
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());

  const filtered = useMemo(() => {
    let result = executions;
    if (filterTrigger !== "all") result = result.filter((e) => e.triggerType === filterTrigger);
    if (filterOutcome !== "all") result = result.filter((e) => e.outcome === filterOutcome);
    if (errorsOnly) result = result.filter((e) => e.outcome === "error" || e.errors > 0);
    return result;
  }, [executions, filterTrigger, filterOutcome, errorsOnly]);

  const grouped = useMemo(() => {
    const groups = new Map<string, TimelineExecution[]>();
    filtered.forEach((exec) => {
      const group = getTimeGroup(exec.startedAt);
      if (!groups.has(group)) groups.set(group, []);
      groups.get(group)?.push(exec);
    });
    return groups;
  }, [filtered]);

  function toggleGroup(group: string) {
    setCollapsedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(group)) next.delete(group);
      else next.add(group);
      return next;
    });
  }

  return (
    <div className="flex flex-col gap-5 p-4 md:p-8">
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-1.5">
          <span className="text-xs text-muted-foreground">Trigger:</span>
          <button
            onClick={() => setFilterTrigger("all")}
            className={cn(
              "rounded-full border px-2 py-0.5 text-[10px] font-medium transition-colors",
              filterTrigger === "all"
                ? "border-primary/30 bg-primary/10 text-primary"
                : "border-border text-muted-foreground hover:text-foreground",
            )}
          >
            All
          </button>
          {triggerTypes.map((triggerType) => (
            <button key={triggerType} onClick={() => setFilterTrigger(filterTrigger === triggerType ? "all" : triggerType)}>
              <TriggerBadge
                type={triggerType}
                size="sm"
                className={cn(
                  "cursor-pointer transition-opacity",
                  filterTrigger !== "all" && filterTrigger !== triggerType && "opacity-40",
                )}
              />
            </button>
          ))}
        </div>

        <div className="h-4 w-px bg-border" />

        <div className="flex items-center gap-1.5">
          <span className="text-xs text-muted-foreground">Outcome:</span>
          <button
            onClick={() => setFilterOutcome("all")}
            className={cn(
              "rounded-full border px-2 py-0.5 text-[10px] font-medium transition-colors",
              filterOutcome === "all"
                ? "border-primary/30 bg-primary/10 text-primary"
                : "border-border text-muted-foreground hover:text-foreground",
            )}
          >
            All
          </button>
          {outcomeTypes.map((outcomeType) => (
            <button key={outcomeType} onClick={() => setFilterOutcome(filterOutcome === outcomeType ? "all" : outcomeType)}>
              <OutcomeBadge
                outcome={outcomeType}
                className={cn(
                  "cursor-pointer transition-opacity",
                  filterOutcome !== "all" && filterOutcome !== outcomeType && "opacity-40",
                )}
              />
            </button>
          ))}
        </div>

        <div className="h-4 w-px bg-border" />

        <label className="flex items-center gap-1.5 text-xs">
          <input
            type="checkbox"
            checked={errorsOnly}
            onChange={(event) => setErrorsOnly(event.target.checked)}
            className="h-3.5 w-3.5 rounded border-border bg-secondary accent-primary"
          />
          <span className="text-muted-foreground">Only errors</span>
        </label>
      </div>

      {filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-xl border border-border bg-card py-16">
          <p className="text-sm text-muted-foreground">No executions match your filters</p>
        </div>
      ) : (
        <div className="flex flex-col gap-1">
          {Array.from(grouped.entries()).map(([group, items]) => {
            const isCollapsed = collapsedGroups.has(group);
            return (
              <div key={group}>
                <button
                  onClick={() => toggleGroup(group)}
                  className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground transition-colors hover:bg-secondary/30"
                >
                  {isCollapsed ? <ChevronRight className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
                  {group}
                  <span className="ml-1 rounded-full bg-secondary px-1.5 py-0.5 text-[10px] font-medium text-foreground">
                    {items.length}
                  </span>
                </button>

                {!isCollapsed ? (
                  <div className="relative ml-5 border-l-2 border-border pl-0">
                    {items.map((execution) => (
                      <Link
                        key={execution.executionId}
                        href={`/executions?focusExecutionId=${encodeURIComponent(execution.executionId)}&search=${encodeURIComponent(execution.executionId)}`}
                        className="group relative mb-2 ml-4 block rounded-lg border border-border bg-card p-3 transition-colors hover:bg-secondary/30"
                      >
                        <div
                          className={cn(
                            "absolute -left-[22px] top-4 h-2.5 w-2.5 rounded-full border-2 border-background",
                            execution.outcome === "completed"
                              ? "bg-emerald-400"
                              : execution.outcome === "error"
                                ? "bg-rose-400"
                                : execution.outcome === "blocked"
                                  ? "bg-amber-400"
                                  : "animate-pulse bg-sky-400",
                          )}
                        />

                        <div className="flex items-start justify-between gap-4">
                          <div className="min-w-0 flex-1">
                            <div className="mb-1 flex items-center gap-2">
                              <TriggerBadge type={execution.triggerType} size="sm" />
                              <span className="truncate font-mono text-sm text-foreground">{execution.triggerSource}</span>
                              {execution.triggerRef ? (
                                <span className="truncate font-mono text-[10px] text-muted-foreground">ref: {execution.triggerRef}</span>
                              ) : null}
                            </div>

                            <div className="flex items-center gap-4 text-xs text-muted-foreground">
                              <div className="flex items-center gap-1">
                                <Wrench className="h-3 w-3" />
                                <span className="font-medium text-foreground">{execution.toolCalls}</span> tools
                              </div>
                              <div className="flex items-center gap-1">
                                <Globe className="h-3 w-3" />
                                <span className="font-medium text-foreground">{execution.domainsTouched}</span> domains
                              </div>
                              {execution.errors > 0 ? (
                                <div className="flex items-center gap-1 text-rose-400">
                                  <AlertTriangle className="h-3 w-3" />
                                  <span className="font-medium">{execution.errors}</span> errors
                                </div>
                              ) : null}
                              {execution.alertsRaised > 0 ? (
                                <div className="flex items-center gap-1 text-amber-400">
                                  <AlertTriangle className="h-3 w-3" />
                                  <span className="font-medium">{execution.alertsRaised}</span> alerts
                                </div>
                              ) : null}
                            </div>
                          </div>

                          <div className="flex shrink-0 flex-col items-end gap-1">
                            <div className="flex items-center gap-2">
                              <span className="text-xs tabular-nums text-muted-foreground">{formatTime(execution.startedAt)}</span>
                              <span className="text-xs tabular-nums text-muted-foreground">{formatDuration(execution.durationMs)}</span>
                            </div>
                            <OutcomeBadge outcome={execution.outcome} />
                          </div>
                        </div>

                        <div className="mt-1.5 flex items-center gap-2">
                          <span className="font-mono text-[10px] text-primary">{execution.executionId}</span>
                          {execution.parentExecutionId ? (
                            <span className="text-[10px] text-muted-foreground">
                              child of <span className="font-mono text-primary">{execution.parentExecutionId}</span>
                            </span>
                          ) : null}
                        </div>
                      </Link>
                    ))}
                  </div>
                ) : null}
              </div>
            );
          })}
        </div>
      )}

      <p className="text-xs text-muted-foreground">
        Showing {filtered.length} of {executions.length} executions
      </p>
    </div>
  );
}
