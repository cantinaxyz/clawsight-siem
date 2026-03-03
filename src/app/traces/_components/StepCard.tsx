/**
 * @fileoverview ClawSight SIEM module: platform/src/app/traces/_components/StepCard.tsx.
 */
"use client";

import { useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import type { TraceMode, TraceStep } from "@/lib/traces/types";
import StepDetailsPanel from "@/app/traces/_components/StepDetailsPanel";

type StepCardProps = {
  step: TraceStep;
  mode: TraceMode;
  showInternal: boolean;
  autoExpandError?: boolean;
};

function formatDuration(durationMs?: number): string {
  if (durationMs == null || !Number.isFinite(durationMs)) return "-";
  if (durationMs < 1000) return `${durationMs}ms`;
  return `${(durationMs / 1000).toFixed(1)}s`;
}

function typeLabel(type: TraceStep["type"]): string {
  if (type === "user_input") return "Message";
  if (type === "model_prep") return "Model prep";
  if (type === "tool_call") return "Tool call";
  if (type === "assistant_response") return "Assistant";
  if (type === "completion") return "Completion";
  if (type === "policy") return "Policy";
  return "Internal";
}

export default function StepCard({
  step,
  mode,
  showInternal,
  autoExpandError = false,
}: StepCardProps) {
  const autoOpen = Boolean(autoExpandError && (step.status === "error" || step.status === "block"));
  const [manualOpen, setManualOpen] = useState<boolean | null>(null);
  const open = manualOpen ?? autoOpen;

  const statusClass =
    step.status === "block"
      ? "border-amber-400/45 bg-amber-500/10 text-amber-200"
      : step.status === "error"
      ? "border-destructive/40 bg-destructive/10 text-destructive"
      : step.status === "warn"
        ? "border-amber-500/35 bg-amber-500/10 text-amber-300"
      : "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";

  return (
    <div className="rounded-md border border-border bg-card p-3">
      <div className="mb-1 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">{typeLabel(step.type)}</span>
          {step.status ? (
            <Badge variant="outline" className={cn("text-[10px]", statusClass)}>
              {step.status}
            </Badge>
          ) : null}
        </div>
        <span className="font-mono text-xs text-muted-foreground">{step.ts}</span>
      </div>

      <p className="text-sm font-medium text-foreground">{step.title}</p>
      {step.summary ? <p className="mt-1 text-sm text-muted-foreground">{step.summary}</p> : null}

      <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
        {step.durationMs != null ? <span>{formatDuration(step.durationMs)}</span> : null}
        {step.toolName ? <span>tool: {step.toolName}</span> : null}
        {step.targetDomain ? <span>domain: {step.targetDomain}</span> : null}
        <span>{step.events.length} event{step.events.length === 1 ? "" : "s"}</span>
      </div>

      {mode !== "narrative" ? (
        <div className="mt-2">
          <Button type="button" variant="ghost" size="sm" onClick={() => setManualOpen(!open)}>
            {open ? <ChevronDown className="mr-1 h-4 w-4" /> : <ChevronRight className="mr-1 h-4 w-4" />}
            {open ? "Hide details" : "Show details"}
          </Button>
        </div>
      ) : null}

      {mode !== "narrative" && open ? (
        <StepDetailsPanel step={step} mode={mode} showInternal={showInternal} />
      ) : null}
    </div>
  );
}
