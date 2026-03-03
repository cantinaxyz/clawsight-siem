/**
 * @fileoverview ClawSight SIEM module: platform/src/app/traces/_components/RawEventsViewer.tsx.
 */
"use client";

import type { TraceEvent } from "@/lib/traces/types";

type RawEventsViewerProps = {
  events: TraceEvent[];
};

export default function RawEventsViewer({ events }: RawEventsViewerProps) {
  if (events.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-card p-4 text-sm text-muted-foreground">
        No events match the current filters.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {events.map((event) => (
        <details key={event.id} className="rounded-lg border border-border bg-card p-3">
          <summary className="cursor-pointer text-sm font-medium text-foreground">
            {event.ts} · {event.name}
          </summary>
          <pre className="mt-3 max-h-[420px] overflow-auto rounded-md bg-secondary/60 p-3 text-xs text-foreground">
            {JSON.stringify(event, null, 2)}
          </pre>
        </details>
      ))}
    </div>
  );
}
