/**
 * @fileoverview ClawSight SIEM module: platform/src/app/traces/_components/TraceListItem.tsx.
 */
"use client";

import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { TraceSummary } from "@/lib/traces/types";
import { AlertTriangle, Ban, CircleX } from "lucide-react";

type TraceListItemProps = {
  trace: TraceSummary;
  selected: boolean;
  onSelect: (traceId: string) => void;
};

function formatTime(value: string): string {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return "-";
  return date.toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

function runStatusClass(status: TraceSummary["runStatus"]): string {
  if (status === "completed") return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
  if (status === "failed") return "border-destructive/40 bg-destructive/10 text-destructive";
  return "border-primary/40 bg-primary/10 text-primary";
}

function cardClass(trace: TraceSummary, selected: boolean): string {
  const selectedRing = selected ? "ring-1 ring-primary/40" : "";
  if (trace.blockCount > 0) {
    return cn(
      "border-amber-400/45 bg-amber-500/10 hover:bg-amber-500/15",
      selectedRing,
    );
  }
  if (trace.errorCount > 0) {
    return cn(
      "border-destructive/45 bg-destructive/10 hover:bg-destructive/15",
      selectedRing,
    );
  }
  if (trace.warnCount > 0) {
    return cn(
      "border-yellow-400/35 bg-yellow-500/10 hover:bg-yellow-500/15",
      selectedRing,
    );
  }
  return cn(selected ? "border-primary/30 bg-accent" : "border-border bg-card hover:bg-secondary", selectedRing);
}

function countChipClass(type: "block" | "error" | "warn"): string {
  if (type === "block") return "border-amber-400/40 bg-amber-500/10 text-amber-200";
  if (type === "error") return "border-destructive/40 bg-destructive/10 text-destructive";
  return "border-yellow-400/35 bg-yellow-500/10 text-yellow-200";
}

export default function TraceListItem({ trace, selected, onSelect }: TraceListItemProps) {
  return (
    <button
      type="button"
      onClick={() => onSelect(trace.traceId)}
      className={cn(
        "w-full rounded-lg border border-border p-3 text-left transition-colors",
        cardClass(trace, selected),
      )}
    >
      <div className="mb-1 flex items-center justify-between gap-2">
        <span className="truncate font-mono text-xs text-primary">{trace.requestKey || trace.traceId}</span>
        <Badge
          variant="outline"
          className={cn(
            "shrink-0 text-[10px]",
            trace.blockCount > 0
              ? "border-amber-400/45 bg-amber-500/10 text-amber-200"
              : runStatusClass(trace.runStatus),
          )}
        >
          {trace.runStatus}
        </Badge>
      </div>

      <p className="truncate text-xs text-muted-foreground">{trace.traceId}</p>

      <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
        <span>{trace.source}</span>
        <span>{trace.spansCount} spans</span>
        {trace.blockCount > 0 ? (
          <span
            className={cn(
              "inline-flex items-center gap-1 rounded-full border px-1.5 py-0.5 text-[11px] font-medium",
              countChipClass("block"),
            )}
            title={`${trace.blockCount} policy blocks`}
            aria-label={`${trace.blockCount} policy blocks`}
          >
            <Ban className="h-3.5 w-3.5" />
            <span>{trace.blockCount}</span>
          </span>
        ) : null}
        {trace.errorCount > 0 ? (
          <span
            className={cn(
              "inline-flex items-center gap-1 rounded-full border px-1.5 py-0.5 text-[11px] font-medium",
              countChipClass("error"),
            )}
            title={`${trace.errorCount} errors`}
            aria-label={`${trace.errorCount} errors`}
          >
            <CircleX className="h-3.5 w-3.5" />
            <span>{trace.errorCount}</span>
          </span>
        ) : null}
        {trace.warnCount > 0 ? (
          <span
            className={cn(
              "inline-flex items-center gap-1 rounded-full border px-1.5 py-0.5 text-[11px] font-medium",
              countChipClass("warn"),
            )}
            title={`${trace.warnCount} warnings`}
            aria-label={`${trace.warnCount} warnings`}
          >
            <AlertTriangle className="h-3.5 w-3.5" />
            <span>{trace.warnCount}</span>
          </span>
        ) : null}
        <span>{formatTime(trace.startedAt)}</span>
      </div>
    </button>
  );
}
