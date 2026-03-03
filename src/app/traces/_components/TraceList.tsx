/**
 * @fileoverview ClawSight SIEM module: platform/src/app/traces/_components/TraceList.tsx.
 */
"use client";

import TraceListItem from "@/app/traces/_components/TraceListItem";
import type { TraceSummary } from "@/lib/traces/types";

type TraceListProps = {
  traces: TraceSummary[];
  selectedTraceId?: string;
  total: number;
  onSelectTrace: (traceId: string) => void;
};

export default function TraceList({ traces, selectedTraceId, total, onSelectTrace }: TraceListProps) {
  return (
    <div className="w-full xl:w-80 xl:flex-shrink-0">
      <div className="mb-2 flex items-center justify-between">
        <p className="text-sm font-semibold text-foreground">Traces</p>
        <p className="text-xs text-muted-foreground">
          {traces.length}/{total}
        </p>
      </div>

      <div className="flex max-h-[calc(100vh-260px)] flex-col gap-2 overflow-auto pr-1">
        {traces.length === 0 ? (
          <div className="rounded-lg border border-dashed border-border bg-card p-4 text-sm text-muted-foreground">
            No traces found for the current filters.
          </div>
        ) : (
          traces.map((trace) => (
            <TraceListItem
              key={trace.traceId}
              trace={trace}
              selected={trace.traceId === selectedTraceId}
              onSelect={onSelectTrace}
            />
          ))
        )}
      </div>
    </div>
  );
}
