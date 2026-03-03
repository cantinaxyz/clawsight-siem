/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/traces/search.ts.
 */
import type { TraceEvent, TraceStep, TraceTab } from "@/lib/traces/types";

function matchesTab(event: TraceEvent, tab: TraceTab): boolean {
  if (tab === "all") return true;
  if (tab === "messages") return event.kind === "message";
  if (tab === "tools") return event.kind === "tool";
  if (tab === "policy") return event.kind === "policy";
  return true;
}

function matchesQuery(event: TraceEvent, needle: string): boolean {
  if (!needle) return true;
  const haystack = [
    event.name,
    event.summary,
    event.toolName,
    event.targetUrl,
    event.targetDomain,
    event.argsPreview,
    event.resultCode,
    event.artifacts?.map((item) => [item.label, item.fileName, item.filePath, item.url, item.mimeType].filter(Boolean).join(" ")).join(" "),
    event.ts,
  ]
    .filter(Boolean)
    .join("\n")
    .toLowerCase();
  return haystack.includes(needle);
}

export function filterEvents(events: TraceEvent[], query: string): TraceEvent[] {
  const needle = query.trim().toLowerCase();
  if (!needle) return events;
  return events.filter((event) => matchesQuery(event, needle));
}

export function filterSteps(
  steps: TraceStep[],
  options: { tab: TraceTab; showInternal: boolean; query: string },
): TraceStep[] {
  const needle = options.query.trim().toLowerCase();

  return steps
    .map((step) => {
      const events = step.events.filter((event) => {
        if (!options.showInternal && event.kind === "internal") return false;
        if (!matchesTab(event, options.tab)) return false;
        if (!matchesQuery(event, needle)) return false;
        return true;
      });

      const internalEvents = (step.internalEvents || []).filter((event) => {
        if (!options.showInternal) return false;
        if (!matchesTab(event, options.tab)) return false;
        if (!matchesQuery(event, needle)) return false;
        return true;
      });

      return {
        ...step,
        events,
        internalEvents,
      };
    })
    .filter((step) => step.events.length > 0 || (step.internalEvents?.length ?? 0) > 0);
}
