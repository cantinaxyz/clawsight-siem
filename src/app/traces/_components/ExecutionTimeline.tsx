/**
 * @fileoverview ClawSight SIEM module: platform/src/app/traces/_components/ExecutionTimeline.tsx.
 */
"use client";

import { useMemo, useState } from "react";
import { Bot, CheckCircle2, ChevronDown, ChevronRight, Cpu, MessageSquare, Wrench } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import StepCard from "@/app/traces/_components/StepCard";
import RawEventsViewer from "@/app/traces/_components/RawEventsViewer";
import { deriveSteps } from "@/lib/traces/deriveSteps";
import { filterEvents, filterSteps } from "@/lib/traces/search";
import type { TraceDetail, TraceMode, TraceTab } from "@/lib/traces/types";

type ExecutionTimelineProps = {
  detail: TraceDetail;
  mode: TraceMode;
  tab: TraceTab;
  showInternal: boolean;
  query: string;
};

function matchesTab(kind: string, tab: TraceTab): boolean {
  if (tab === "all") return true;
  if (tab === "messages") return kind === "message";
  if (tab === "tools") return kind === "tool";
  if (tab === "policy") return kind === "policy";
  return true;
}

function groupKeyForStepType(type: ReturnType<typeof deriveSteps>[number]["type"]): string {
  if (type === "user_input") return "user_input";
  if (type === "model_prep") return "model_prep";
  if (type === "tool_call" || type === "policy") return "execution";
  if (type === "assistant_response") return "assistant";
  if (type === "completion") return "completion";
  return "internal";
}

function groupLabel(key: string): string {
  if (key === "user_input") return "User Input";
  if (key === "model_prep") return "Model Preparation";
  if (key === "execution") return "Agent Execution";
  if (key === "assistant") return "Assistant Response";
  if (key === "completion") return "Completion";
  return "Internal Lifecycle";
}

function buildStepGroups(
  steps: ReturnType<typeof deriveSteps>,
): Array<{ key: string; label: string; steps: ReturnType<typeof deriveSteps> }> {
  const order = ["user_input", "model_prep", "execution", "assistant", "completion", "internal"];
  const buckets = new Map<string, ReturnType<typeof deriveSteps>>();
  for (const key of order) buckets.set(key, []);

  for (const step of steps) {
    const key = groupKeyForStepType(step.type);
    const bucket = buckets.get(key);
    if (bucket) {
      bucket.push(step);
    } else {
      buckets.set(key, [step]);
    }
  }

  return order
    .map((key) => ({ key, label: groupLabel(key), steps: buckets.get(key) || [] }))
    .filter((group) => group.steps.length > 0);
}

function groupVisuals(groupKey: string): {
  icon: typeof MessageSquare;
  panel: string;
  node: string;
} {
  if (groupKey === "execution") {
    return {
      icon: Wrench,
      panel: "border-amber-500/35 bg-amber-500/5",
      node: "border-amber-500/40 bg-amber-500/10",
    };
  }
  if (groupKey === "model_prep") {
    return {
      icon: Bot,
      panel: "border-violet-500/35 bg-violet-500/5",
      node: "border-violet-500/40 bg-violet-500/10",
    };
  }
  if (groupKey === "assistant") {
    return {
      icon: Bot,
      panel: "border-fuchsia-500/35 bg-fuchsia-500/5",
      node: "border-fuchsia-500/40 bg-fuchsia-500/10",
    };
  }
  if (groupKey === "completion") {
    return {
      icon: CheckCircle2,
      panel: "border-emerald-500/35 bg-emerald-500/5",
      node: "border-emerald-500/40 bg-emerald-500/10",
    };
  }
  if (groupKey === "internal") {
    return {
      icon: Cpu,
      panel: "border-border bg-secondary/20",
      node: "border-border bg-secondary",
    };
  }
  return {
    icon: MessageSquare,
    panel: "border-sky-500/35 bg-sky-500/5",
    node: "border-sky-500/40 bg-sky-500/10",
  };
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

function truncate(value: string, max = 180): string {
  return value.length <= max ? value : `${value.slice(0, max)}...`;
}

function formatDuration(durationMs?: number): string {
  if (durationMs == null || !Number.isFinite(durationMs)) return "-";
  if (durationMs < 1000) return `${durationMs}ms`;
  return `${(durationMs / 1000).toFixed(1)}s`;
}

function extractMessagePreview(payload: unknown): string | undefined {
  const rec = asRecord(payload);
  const body = asRecord(rec?.body);
  const metadata = asRecord(rec?.metadata);
  const context = asRecord(rec?.context);
  return (
    asString(rec?.body) ||
    asString(rec?.content) ||
    asString(rec?.text) ||
    asString(body?.preview) ||
    asString(rec?.promptPreview) ||
    asString(rec?.prompt) ||
    asString(metadata?.message) ||
    asString(context?.message) ||
    undefined
  );
}

function buildNarrativeLines(detail: TraceDetail, groupKey: string, groupSteps: ReturnType<typeof deriveSteps>): string[] {
  if (groupKey === "user_input") {
    const firstMessageEvent = groupSteps
      .flatMap((step) => step.events)
      .find((event) => event.kind === "message");
    const preview = extractMessagePreview(firstMessageEvent?.payload);
    const source = detail.messageProvider || detail.triggerType;
    const lines = [preview ? `User input received: "${truncate(preview, 220)}".` : "User input received."];
    if (source) {
      lines.push(`Source detected as ${source}.`);
    }
    return lines;
  }

  if (groupKey === "model_prep") {
    const parts: string[] = [];
    if (detail.model) parts.push(`model ${detail.model}`);
    if (typeof detail.contextHistoryCount === "number") parts.push(`history ${detail.contextHistoryCount} messages`);
    if (typeof detail.promptBytes === "number") parts.push(`prompt ${detail.promptBytes} bytes`);
    return [
      parts.length > 0
        ? `Model preparation completed with ${parts.join(", ")}.`
        : "Model preparation completed.",
    ];
  }

  if (groupKey === "execution") {
    const toolSteps = groupSteps.filter((step) => step.type === "tool_call");
    const policySteps = groupSteps.filter((step) => step.type === "policy");
    const toolNames = Array.from(new Set(toolSteps.map((step) => step.toolName).filter(Boolean) as string[]));
    const domains = Array.from(new Set(toolSteps.map((step) => step.targetDomain).filter(Boolean) as string[]));
    const toolErrorCount = toolSteps.filter((step) => step.status === "error").length;
    const blockCount = policySteps.filter((step) => step.status === "block").length;

    const lines: string[] = [];
    if (toolSteps.length > 0) {
      lines.push(
        `Agent executed ${toolSteps.length} tool call${toolSteps.length === 1 ? "" : "s"}${
          toolNames.length > 0 ? ` using ${toolNames.slice(0, 4).join(", ")}${toolNames.length > 4 ? ", ..." : ""}` : ""
        }.`,
      );
    } else {
      lines.push("No external tool calls were needed.");
    }

    if (domains.length > 0) {
      lines.push(`Domains touched: ${domains.slice(0, 6).join(", ")}${domains.length > 6 ? ", ..." : ""}.`);
    }
    if (toolErrorCount > 0 || blockCount > 0) {
      lines.push(
        `Execution issues observed: ${toolErrorCount} tool error${toolErrorCount === 1 ? "" : "s"}, ${blockCount} policy block${blockCount === 1 ? "" : "s"}.`,
      );
    }
    return lines;
  }

  if (groupKey === "assistant") {
    const assistantStep = groupSteps.find((step) => step.type === "assistant_response");
    const summary = assistantStep?.summary ? truncate(assistantStep.summary, 220) : undefined;
    const lines = [summary ? `Assistant response generated: ${summary}` : "Assistant response generated."];
    if (typeof detail.tokensIn === "number" || typeof detail.tokensOut === "number") {
      lines.push(`Token usage: in ${detail.tokensIn ?? "-"} / out ${detail.tokensOut ?? "-"}.`);
    }
    return lines;
  }

  if (groupKey === "completion") {
    const status = detail.runStatus;
    return [
      `Execution ${status} in ${formatDuration(detail.durationMs)}.`,
      `${detail.errorCount} error${detail.errorCount === 1 ? "" : "s"} and ${detail.blockCount} policy block${
        detail.blockCount === 1 ? "" : "s"
      } recorded.`,
    ];
  }

  return ["Internal lifecycle events were recorded."];
}

export default function ExecutionTimeline({ detail, mode, tab, showInternal, query }: ExecutionTimelineProps) {
  const steps = useMemo(() => deriveSteps(detail), [detail]);
  const filteredSteps = useMemo(
    () => filterSteps(steps, { tab, showInternal, query }),
    [steps, tab, showInternal, query],
  );
  const groups = useMemo(() => buildStepGroups(filteredSteps), [filteredSteps]);
  const [expandedGroupsState, setExpandedGroupsState] = useState<Set<string>>(new Set());

  const rawEvents = useMemo(() => {
    const base = detail.events.filter((event) => {
      if (!showInternal && event.kind === "internal") return false;
      return matchesTab(event.kind, tab);
    });
    return filterEvents(base, query);
  }, [detail.events, tab, showInternal, query]);

  const alertGroupKeys = useMemo(
    () =>
      new Set(
        groups
          .filter((group) => group.steps.some((step) => step.status === "error" || step.status === "block"))
          .map((group) => group.key),
      ),
    [groups],
  );

  const expandedGroups = useMemo(() => {
    const next = new Set<string>();
    for (const group of groups) {
      if (expandedGroupsState.has(group.key)) {
        next.add(group.key);
      }
    }
    for (const key of alertGroupKeys) {
      next.add(key);
    }
    return next;
  }, [groups, alertGroupKeys, expandedGroupsState]);

  function toggleGroup(groupKey: string) {
    setExpandedGroupsState((prev) => {
      const next = new Set(prev);
      if (next.has(groupKey)) {
        next.delete(groupKey);
      } else {
        next.add(groupKey);
      }
      return next;
    });
  }

  if (mode === "raw") {
    return <RawEventsViewer events={rawEvents} />;
  }

  if (filteredSteps.length === 0 || groups.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-card p-4 text-sm text-muted-foreground">
        No narrative phases match the current filters.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {groups.map((group) => {
        const isOpen = expandedGroups.has(group.key);
        const groupBlockCount = group.steps.filter((step) => step.status === "block").length;
        const groupErrorCount = group.steps.filter((step) => step.status === "error").length;
        const visuals = groupVisuals(group.key);
        const GroupIcon = visuals.icon;
        const lines = buildNarrativeLines(detail, group.key, group.steps);

        return (
          <div key={group.key} className={cn("rounded-lg border", visuals.panel)}>
            <button
              type="button"
              onClick={() => toggleGroup(group.key)}
              className="flex w-full items-center justify-between gap-3 px-3 py-2 text-left"
            >
              <div className="flex items-center gap-2">
                <div
                  className={cn(
                    "flex h-8 w-8 items-center justify-center rounded-full border-2",
                    visuals.node,
                  )}
                >
                  <GroupIcon className="h-4 w-4" />
                </div>
                {isOpen ? (
                  <ChevronDown className="h-4 w-4 text-muted-foreground" />
                ) : (
                  <ChevronRight className="h-4 w-4 text-muted-foreground" />
                )}
                <p className="text-sm font-medium text-foreground">{group.label}</p>
              </div>
              <div className="flex items-center gap-2">
                {groupBlockCount > 0 ? (
                  <Badge variant="outline" className="border-amber-400/45 bg-amber-500/10 text-amber-200">
                    {groupBlockCount} policy blocks
                  </Badge>
                ) : null}
                {groupErrorCount > 0 ? (
                  <Badge variant="outline" className="border-destructive/40 bg-destructive/10 text-destructive">
                    {groupErrorCount} errors
                  </Badge>
                ) : null}
                <Badge variant="outline" className="text-[10px]">
                  {group.steps.length} step{group.steps.length === 1 ? "" : "s"}
                </Badge>
              </div>
            </button>

            <div className="px-3 pb-3">
              <ul className="space-y-1 pl-4 text-sm text-muted-foreground">
                {lines.map((line, index) => (
                  <li key={`${group.key}-${index}`} className="list-disc">
                    {line}
                  </li>
                ))}
              </ul>
            </div>

            {isOpen ? (
              <div className="border-t border-border/60 p-3">
                <div className="space-y-2">
                  {group.steps.map((step, index) => (
                    <StepCard
                      key={step.id}
                      step={step}
                      mode="technical"
                      showInternal={showInternal}
                      autoExpandError={index === 0 && detail.runStatus === "failed"}
                    />
                  ))}
                </div>
              </div>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}
