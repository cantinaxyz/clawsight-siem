/**
 * @fileoverview ClawSight SIEM module: platform/src/components/telemetry-event-stream.tsx.
 */
"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import {
  Activity,
  Bot,
  ChevronRight,
  CircleDot,
  Clock3,
  ExternalLink,
  FileText,
  Flag,
  Globe,
  Hash,
  MessageSquare,
  Shield,
  Wrench,
  type LucideIcon,
} from "lucide-react";
import type { SerializedTelemetryEvent } from "@/lib/telemetry-event-query";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { buildTelemetryDisplay } from "@/lib/telemetry-display";

type SearchFilters = {
  category?: string;
  outcome?: string;
  policyRuleId?: string;
  projectId?: string;
  requestId?: string;
  agentKey?: string;
  search?: string;
};

type Props = {
  initialEvents: SerializedTelemetryEvent[];
  total: number;
  limit: number;
  filters: SearchFilters;
};

function formatDate(ts: number) {
  return new Date(ts).toLocaleString("en-US", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

function statusBadgeClass(value?: string | null) {
  switch (value) {
    case "block":
    case "blocked":
      return "border-destructive/40 bg-destructive/10 text-destructive";
    case "error":
      return "border-destructive/40 bg-destructive/10 text-destructive";
    case "warn":
      return "border-yellow-500/30 bg-yellow-500/10 text-yellow-300";
    case "modify":
    case "modified":
      return "border-orange-500/30 bg-orange-500/10 text-orange-300";
    case "submitted":
    case "ok":
    case "allow":
      return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
    default:
      return "border-border bg-secondary text-secondary-foreground";
  }
}

function effectiveEventOutcome(event: SerializedTelemetryEvent): string | null {
  const rawOutcome = String(event.outcome || event.result || "").trim().toLowerCase();
  if (!rawOutcome) return null;
  if (
    rawOutcome === "error" &&
    String(event.category || "").toLowerCase() === "tool" &&
    String(event.action || "").toLowerCase() === "after_tool_call" &&
    String(event.severity || "").toLowerCase() === "debug"
  ) {
    const reason = String(event.outcomeReason || "").toLowerCase();
    if (
      reason.includes("blocked") ||
      reason.includes("deny") ||
      reason.includes("denied") ||
      reason.includes("local rule")
    ) {
      return "block";
    }
    return "warn";
  }
  return rawOutcome;
}

function toPreview(value: unknown, max = 160): string {
  if (!value) return "-";
  if (typeof value === "string") {
    return value.length <= max ? value : `${value.slice(0, max)}...`;
  }
  try {
    const raw = JSON.stringify(value);
    return raw.length <= max ? raw : `${raw.slice(0, max)}...`;
  } catch {
    return String(value).slice(0, max);
  }
}

function toJsonText(value: unknown): string {
  if (value == null) return "null";
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function artifactBadgeLabel(artifact: {
  kind: "file" | "url" | "media";
  fileName?: string;
  filePath?: string;
  url?: string;
  label?: string;
  mimeType?: string;
}) {
  const base =
    artifact.fileName ??
    artifact.filePath ??
    artifact.url ??
    artifact.label ??
    artifact.kind;
  if (artifact.mimeType) {
    return `${base} (${artifact.mimeType})`;
  }
  return base;
}

function compactExecutionLabel(traceId?: string | null): string {
  const raw = String(traceId || "").trim();
  if (!raw) return "-";
  const parts = raw.split(":").filter(Boolean);
  if (parts[0] === "msg") {
    const channel = (parts[1] || "MSG").slice(0, 3).toUpperCase();
    const leaf = (parts[parts.length - 1] || "").replace(/[^a-zA-Z0-9]/g, "");
    return `${channel}-${(leaf || "EXEC").slice(-6).toUpperCase()}`;
  }
  if (parts[0] === "agent" && parts[parts.length - 1] === "bootstrap") {
    return "SYSTEM-BOOT";
  }
  const tail = parts[parts.length - 1] || raw;
  return tail.length <= 16 ? tail : `${tail.slice(0, 16)}...`;
}

function compactRef(value?: string | null, max = 22): string {
  const raw = String(value || "").trim();
  if (!raw) return "-";
  return raw.length <= max ? raw : `${raw.slice(0, max)}...`;
}

const categoryIconMap: Record<string, LucideIcon> = {
  tool: Wrench,
  policy: Shield,
  session: Clock3,
  message: MessageSquare,
  agent: Bot,
  gateway: Globe,
  diagnostic: Activity,
  log: FileText,
};

function iconForCategory(category?: string | null): LucideIcon {
  const key = String(category || "").trim().toLowerCase();
  return categoryIconMap[key] ?? CircleDot;
}

export default function TelemetryEventStream({ initialEvents, total, limit, filters }: Props) {
  const [events, setEvents] = useState(initialEvents);
  const [totalEvents, setTotalEvents] = useState(total);
  const [connectionLabel, setConnectionLabel] = useState("Connecting...");
  const [connected, setConnected] = useState(false);
  const [expandedEventId, setExpandedEventId] = useState<number | null>(null);
  const cursorTs = initialEvents[0]?.ts;
  const cursorId = initialEvents[0]?.id;

  useEffect(() => {
    const params = new URLSearchParams();
    if (filters.category) params.set("category", filters.category);
    if (filters.outcome) params.set("outcome", filters.outcome);
    if (filters.policyRuleId) params.set("policyRuleId", filters.policyRuleId);
    if (filters.requestId) params.set("requestId", filters.requestId);
    if (filters.agentKey) params.set("agentKey", filters.agentKey);
    if (filters.search) params.set("search", filters.search);
    if (cursorTs !== undefined) params.set("cursorTs", String(cursorTs));
    if (cursorId !== undefined) params.set("cursorId", String(cursorId));
    params.set("limit", String(limit));

    const source = new EventSource(`/api/telemetry/events/stream?${params}`);
    const onOpen = () => {
      setConnected(true);
      setConnectionLabel("Live");
    };
    const onError = () => {
      setConnected(false);
      setConnectionLabel("Reconnecting...");
    };

    const onMessage = (event: MessageEvent<string>) => {
      try {
        const payload = JSON.parse(event.data) as SerializedTelemetryEvent;
        setEvents((current) => {
          if (current.some((item) => item.id === payload.id)) {
            return current;
          }
          const next = [payload, ...current];
          if (next.length > limit) {
            next.length = limit;
          }
          return next;
        });
        setTotalEvents((current) => current + 1);
      } catch {
        // ignore malformed frames
      }
    };

    source.addEventListener("telemetry", onMessage);
    source.onopen = onOpen;
    source.onerror = onError;

    return () => {
      source.removeEventListener("telemetry", onMessage);
      source.close();
    };
  }, [
    filters.category,
    filters.outcome,
    filters.policyRuleId,
    filters.projectId,
    filters.agentKey,
    filters.requestId,
    filters.search,
    cursorId,
    cursorTs,
    limit,
  ]);

  return (
    <>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <p className="text-sm text-muted-foreground">
          Showing <span className="font-medium text-foreground">{events.length}</span> / {totalEvents} events
        </p>
        <Badge
          className={cn(
            "ml-auto",
            connected
              ? "border-primary/35 bg-primary/10 text-primary"
              : "border-border bg-secondary text-muted-foreground",
          )}
        >
          SSE {connected ? "Live" : connectionLabel}
        </Badge>
      </div>

      <div className="overflow-hidden rounded-xl border border-border bg-card">
        <div className="grid grid-cols-[190px_170px_1fr_110px_140px_40px] gap-0 border-b border-border bg-muted/30 px-4 py-2.5 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
          <span className="inline-flex items-center gap-1">
            <Clock3 className="h-3 w-3" />
            Time
          </span>
          <span className="inline-flex items-center gap-1">
            <Bot className="h-3 w-3" />
            Agent
          </span>
          <span className="inline-flex items-center gap-1">
            <Activity className="h-3 w-3" />
            Event
          </span>
          <span className="inline-flex items-center gap-1">
            <Flag className="h-3 w-3" />
            Outcome
          </span>
          <span className="inline-flex items-center gap-1">
            <Hash className="h-3 w-3" />
            Execution
          </span>
          <span />
        </div>

        {events.length === 0 ? (
          <div className="flex items-center justify-center py-16 text-sm text-muted-foreground">
            No events yet.
          </div>
        ) : (
          <div className="divide-y divide-border">
            {events.map((event) => {
              const isExpanded = expandedEventId === event.id;
              const effectiveOutcome = effectiveEventOutcome(event);
              const display = buildTelemetryDisplay({
                category: event.category,
                action: event.action,
                payload: event.payload,
                payloadRedacted: event.payloadRedacted,
                toolName: event.openclawToolName,
                outcomeReason: event.outcomeReason,
              });
              const CategoryIcon = iconForCategory(event.category);

              return (
                <div key={event.id}>
                  <button
                    type="button"
                    onClick={() => setExpandedEventId((current) => (current === event.id ? null : event.id))}
                    className={cn(
                      "grid w-full grid-cols-[190px_170px_1fr_110px_140px_40px] gap-0 px-4 py-3 text-left text-sm transition-colors hover:bg-secondary/50",
                      isExpanded && "bg-secondary/30",
                    )}
                  >
                    <span className="font-mono text-xs text-muted-foreground">{formatDate(event.ts)}</span>

                    <div className="min-w-0">
                      <p className="truncate text-xs font-medium text-foreground">
                        {event.agentName || event.agentInstanceId || event.openclawAgentId || "-"}
                      </p>
                      <p className="truncate text-xs text-muted-foreground">
                        {event.openclawAgentId ? `agent:${compactRef(event.openclawAgentId, 18)}` : "agent:-"}
                      </p>
                    </div>

                    <div className="flex min-w-0 flex-col justify-center">
                      <p className="inline-flex min-w-0 items-center gap-1 truncate font-mono text-xs text-foreground">
                        <CategoryIcon className="h-3 w-3 shrink-0 text-muted-foreground" />
                        <span className="truncate">
                          {event.category}.{event.action}
                        </span>
                      </p>
                      {display.summary || event.outcomeReason ? (
                        <p className="truncate text-xs text-muted-foreground">
                          {toPreview(display.summary || event.outcomeReason, 120)}
                        </p>
                      ) : null}
                    </div>

                    <div className="min-w-0 overflow-hidden">
                      {effectiveOutcome ? (
                        <Badge className={statusBadgeClass(effectiveOutcome)}>
                          {effectiveOutcome}
                        </Badge>
                      ) : (
                        <Badge className={statusBadgeClass(event.severity)}>{event.severity || "info"}</Badge>
                      )}
                    </div>

                    <div className="min-w-0">
                      {event.traceId ? (
                        <Link
                          href={`/executions/${encodeURIComponent(event.traceId)}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 font-mono text-xs text-primary hover:underline"
                          title={event.traceId}
                        >
                          {compactExecutionLabel(event.traceId)}
                          <ExternalLink className="h-3 w-3" />
                        </Link>
                      ) : (
                        <span className="text-xs text-muted-foreground">-</span>
                      )}
                    </div>

                    <div className="flex items-center justify-end">
                      <ChevronRight
                        className={cn("h-3.5 w-3.5 text-muted-foreground transition-transform", isExpanded && "rotate-90")}
                      />
                    </div>
                  </button>

                  {isExpanded ? (
                    <div className="border-t border-border bg-muted/20 px-4 py-4">
                      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                        <div className="space-y-3 rounded-lg border border-border bg-card p-3">
                          <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                            Event details
                          </h4>
                          {display.summary ? (
                            <p className="text-xs text-foreground">{toPreview(display.summary, 280)}</p>
                          ) : null}

                          {display.fields.length > 0 ? (
                            <div className="space-y-1">
                              {display.fields.slice(0, 8).map((field) => (
                                <div
                                  key={`${event.id}:${field.label}`}
                                  className="text-xs text-muted-foreground break-words whitespace-pre-wrap"
                                >
                                  <span className="font-medium text-foreground">{field.label}:</span> {field.value}
                                </div>
                              ))}
                            </div>
                          ) : (
                            <p className="text-xs text-muted-foreground">No parsed detail fields.</p>
                          )}

                          {display.artifacts.length > 0 ? (
                            <div className="flex flex-wrap gap-1">
                              {display.artifacts.slice(0, 8).map((artifact, idx) => (
                                <Badge
                                  key={`${event.id}:artifact:${idx}`}
                                  className="border-primary/35 bg-primary/10 text-primary"
                                >
                                  {artifact.kind.toUpperCase()}: {toPreview(artifactBadgeLabel(artifact), 96)}
                                </Badge>
                              ))}
                            </div>
                          ) : null}
                        </div>

                        <div className="space-y-3 rounded-lg border border-border bg-card p-3">
                          <div className="flex items-center justify-between">
                            <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                              Context
                            </h4>
                            {event.traceId ? (
                              <Link
                                href={`/executions/${encodeURIComponent(event.traceId)}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
                              >
                                Open execution
                                <ExternalLink className="h-3 w-3" />
                              </Link>
                            ) : null}
                          </div>

                          <div className="flex flex-wrap gap-1">
                            {event.policyRuleId ? (
                              <Badge className="border-amber-500/30 bg-amber-500/10 text-amber-300">
                                rule: {compactRef(event.policyRuleId, 24)}
                              </Badge>
                            ) : null}
                            {event.requestId ? (
                              <Badge className="border-border bg-secondary text-secondary-foreground">
                                req: {compactRef(event.requestId, 16)}
                              </Badge>
                            ) : null}
                            {event.openclawSessionKey ? (
                              <Badge className="border-border bg-secondary text-secondary-foreground">
                                session: {compactRef(event.openclawSessionKey, 18)}
                              </Badge>
                            ) : null}
                            {event.rootExecutionId ? (
                              <Badge className="border-border bg-secondary text-secondary-foreground">
                                root: {compactExecutionLabel(event.rootExecutionId)}
                              </Badge>
                            ) : null}
                            {event.sourceIp ? (
                              <Badge className="border-border bg-secondary text-secondary-foreground">
                                src: {event.sourceIp}
                              </Badge>
                            ) : null}
                          </div>

                          <details>
                            <summary className="cursor-pointer text-xs text-muted-foreground">
                              Raw payload
                            </summary>
                            <pre className="mt-1 max-h-52 overflow-auto rounded bg-secondary p-2 text-xs text-muted-foreground">
                              {toJsonText(display.payload)}
                            </pre>
                          </details>
                        </div>
                      </div>
                    </div>
                  ) : null}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </>
  );
}
