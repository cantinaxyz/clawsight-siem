/**
 * @fileoverview ClawSight SIEM module: platform/src/app/traces/_components/StepDetailsPanel.tsx.
 */
"use client";

import { Badge } from "@/components/ui/badge";
import type { TraceEvent, TraceMode, TraceStep } from "@/lib/traces/types";

type StepDetailsPanelProps = {
  step: TraceStep;
  mode: TraceMode;
  showInternal: boolean;
};

type ToolCallDetail = {
  id: string;
  toolName: string;
  command?: string;
  target?: string;
  status: "ok" | "error";
  durationMs?: number;
  resultCode?: string;
};

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

function extractMessageText(payload: unknown): string | undefined {
  const rec = asRecord(payload);
  const body = asRecord(rec?.body);
  const content = asRecord(rec?.content);
  const text = asRecord(rec?.text);
  return (
    asString(rec?.body) ||
    asString(rec?.content) ||
    asString(rec?.text) ||
    asString(body?.preview) ||
    asString(content?.preview) ||
    asString(text?.preview) ||
    asString(rec?.prompt) ||
    asString(rec?.promptPreview)
  );
}

function extractCommand(event: TraceEvent): string | undefined {
  if (event.argsPreview) return event.argsPreview;
  const payload = asRecord(event.payload);
  const params = asRecord(payload?.params);
  return (
    asString(params?.command) ||
    asString(params?.path) ||
    asString(params?.file_path) ||
    asString(params?.url) ||
    undefined
  );
}

function collectToolCallDetails(events: TraceEvent[]): ToolCallDetail[] {
  const map = new Map<string, ToolCallDetail>();

  for (const event of events) {
    if (event.kind !== "tool") continue;
    const key = event.toolCallId || event.spanId || event.id;
    const existing = map.get(key);
    const detail: ToolCallDetail = existing || {
      id: key,
      toolName: event.toolName || "tool",
      status: "ok",
    };

    detail.toolName = detail.toolName || event.toolName || "tool";
    detail.command = detail.command || extractCommand(event);
    detail.target = detail.target || event.targetUrl || event.targetDomain;
    detail.resultCode = detail.resultCode || event.resultCode;
    detail.durationMs = detail.durationMs ?? event.durationMs;
    if (event.status === "error") {
      detail.status = "error";
    }

    map.set(key, detail);
  }

  return [...map.values()];
}

function collectUrls(events: TraceEvent[]): string[] {
  const set = new Set<string>();
  for (const event of events) {
    if (event.targetUrl) set.add(event.targetUrl);
    for (const artifact of event.artifacts || []) {
      if (artifact.url) set.add(artifact.url);
    }
  }
  return [...set].slice(0, 20);
}

function collectInputArtifacts(events: TraceEvent[]) {
  const map = new Map<string, { kind: string; label: string }>();

  for (const event of events) {
    for (const artifact of event.artifacts || []) {
      const isInput = artifact.kind === "file" || artifact.kind === "media";
      if (!isInput) continue;
      const label =
        artifact.fileName || artifact.filePath || artifact.label || artifact.mimeType || artifact.kind;
      const key = `${artifact.kind}|${label}|${artifact.source}`;
      if (!map.has(key)) {
        map.set(key, { kind: artifact.kind, label });
      }
    }
  }

  return [...map.values()].slice(0, 20);
}

export default function StepDetailsPanel({ step, mode, showInternal }: StepDetailsPanelProps) {
  const messagePreviews = step.events
    .map((event) => extractMessageText(event.payload))
    .filter((value): value is string => Boolean(value));

  const toolCallDetails = collectToolCallDetails(step.events);
  const urls = collectUrls(step.events);
  const inputArtifacts = collectInputArtifacts(step.events);

  return (
    <div className="space-y-3 pt-3">
      {step.summary ? (
        <p className="text-sm text-muted-foreground">{step.summary}</p>
      ) : null}

      {messagePreviews.length > 0 ? (
        <section className="space-y-2">
          <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Messages</p>
          <div className="space-y-2">
            {messagePreviews.slice(0, 4).map((text, index) => (
              <div key={`${index}:${text.slice(0, 24)}`} className="rounded-md border border-border bg-secondary/30 p-2 text-sm text-foreground">
                {truncate(text, 420)}
              </div>
            ))}
          </div>
        </section>
      ) : null}

      {toolCallDetails.length > 0 ? (
        <section className="space-y-2">
          <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">External tools used</p>
          <div className="space-y-2">
            {toolCallDetails.map((call) => (
              <div key={call.id} className="rounded-md border border-border bg-card p-2 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium text-foreground">{call.toolName}</span>
                  <Badge
                    variant="outline"
                    className={call.status === "error" ? "border-destructive/40 bg-destructive/10 text-destructive" : "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"}
                  >
                    {call.status}
                  </Badge>
                  <span className="text-xs text-muted-foreground">{formatDuration(call.durationMs)}</span>
                </div>
                {call.command ? <p className="mt-1 font-mono text-xs text-foreground">{truncate(call.command, 260)}</p> : null}
                {call.target ? <p className="mt-1 text-xs text-muted-foreground">target: {truncate(call.target, 180)}</p> : null}
                {call.resultCode ? <p className="mt-1 text-xs text-muted-foreground">result: {call.resultCode}</p> : null}
              </div>
            ))}
          </div>
        </section>
      ) : null}

      {inputArtifacts.length > 0 ? (
        <section className="space-y-2">
          <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Received documents/images</p>
          <div className="flex flex-wrap gap-2">
            {inputArtifacts.map((artifact) => (
              <Badge key={`${artifact.kind}:${artifact.label}`} variant="outline" className="font-normal">
                {artifact.kind}: {truncate(artifact.label, 80)}
              </Badge>
            ))}
          </div>
        </section>
      ) : null}

      {urls.length > 0 ? (
        <section className="space-y-2">
          <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Visited URLs</p>
          <ul className="space-y-1 text-xs text-foreground">
            {urls.map((url) => (
              <li key={url} className="rounded-md border border-border bg-secondary/30 px-2 py-1 font-mono">
                {truncate(url, 220)}
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      {mode === "technical" ? (
        <section className="space-y-2">
          <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Events in this step</p>
          <div className="space-y-2">
            {step.events.map((event) => (
              <div key={event.id} className="rounded-md border border-border bg-card p-2">
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <span className="font-medium text-foreground">{event.name}</span>
                  <span className="text-muted-foreground">{event.ts}</span>
                  {event.status ? (
                    <Badge variant="outline" className="text-[10px]">
                      {event.status}
                    </Badge>
                  ) : null}
                </div>
                {event.summary ? <p className="mt-1 text-xs text-muted-foreground">{truncate(event.summary, 300)}</p> : null}
              </div>
            ))}
          </div>
        </section>
      ) : null}

      {showInternal && step.internalEvents && step.internalEvents.length > 0 ? (
        <section className="space-y-2">
          <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Internal hooks</p>
          <div className="space-y-1">
            {step.internalEvents.map((event) => (
              <div key={event.id} className="rounded-md border border-dashed border-border bg-secondary/20 px-2 py-1 text-xs text-muted-foreground">
                {event.ts} · {event.name}
              </div>
            ))}
          </div>
        </section>
      ) : null}

      {mode === "raw" ? (
        <section className="space-y-2">
          <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Raw payloads</p>
          {step.events.map((event) => (
            <details key={`raw:${event.id}`} className="rounded-md border border-border bg-secondary/30 p-2">
              <summary className="cursor-pointer text-xs font-medium text-foreground">{event.name}</summary>
              <pre className="mt-2 max-h-[320px] overflow-auto text-[11px] text-foreground">
                {JSON.stringify(event.payload ?? null, null, 2)}
              </pre>
            </details>
          ))}
        </section>
      ) : null}
    </div>
  );
}
