/**
 * @fileoverview ClawSight SIEM module: platform/src/app/traces/_components/TraceOverviewCard.tsx.
 */
import type { TraceDetail, TraceHighlights } from "@/lib/traces/types";

function formatNumber(value?: number): string {
  if (value == null || !Number.isFinite(value)) return "-";
  return value.toLocaleString();
}

function formatBytes(value?: number): string {
  if (value == null || !Number.isFinite(value)) return "-";
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

function truncate(value: string, max = 180): string {
  return value.length <= max ? value : `${value.slice(0, max)}...`;
}

function toMs(ts?: string): number {
  const parsed = Date.parse(ts || "");
  return Number.isFinite(parsed) ? parsed : 0;
}

function normalizeTarget(value?: string): string {
  return (value || "").trim().toLowerCase();
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-[11px] uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className="mt-1 text-sm font-medium text-foreground">{value}</p>
    </div>
  );
}

type TraceOverviewCardProps = {
  detail: TraceDetail;
  highlights: TraceHighlights;
};

type ToolCallPreview = {
  key: string;
  status: "ok" | "error";
  how?: string;
  target?: string;
  result?: string;
  ts?: string;
};

type ToolCallPreviewInternal = ToolCallPreview & {
  toolCallId?: string;
  spanId?: string;
  parentSpanId?: string;
  targetKey: string;
  tsMs: number;
};

type ToolEventLike = TraceDetail["events"][number];

function matchEventToCall(event: ToolEventLike, calls: ToolCallPreviewInternal[]): ToolCallPreviewInternal | undefined {
  if (calls.length === 0) return undefined;

  if (event.toolCallId) {
    const byToolCallId = calls.find((call) => call.toolCallId && call.toolCallId === event.toolCallId);
    if (byToolCallId) return byToolCallId;
  }

  if (event.parentSpanId) {
    const byParentSpan = calls.find((call) => call.spanId && call.spanId === event.parentSpanId);
    if (byParentSpan) return byParentSpan;
  }
  if (event.spanId) {
    const bySpan = calls.find((call) => call.spanId && call.spanId === event.spanId);
    if (bySpan) return bySpan;
  }

  const eventTargetKey = normalizeTarget(event.targetUrl || event.targetDomain);
  const eventTs = toMs(event.ts);
  if (eventTargetKey) {
    const sameTarget = calls
      .filter((call) => call.targetKey === eventTargetKey)
      .sort((a, b) => Math.abs(a.tsMs - eventTs) - Math.abs(b.tsMs - eventTs));
    if (sameTarget.length > 0) return sameTarget[0];
  }

  const nearestByTime = [...calls].sort((a, b) => Math.abs(a.tsMs - eventTs) - Math.abs(b.tsMs - eventTs));
  return nearestByTime[0];
}

function buildCallsFromBeforeEvents(toolEvents: ToolEventLike[]): ToolCallPreviewInternal[] {
  const beforeEvents = toolEvents
    .filter((event) => event.name === "tool.before_tool_call")
    .sort((a, b) => toMs(a.ts) - toMs(b.ts));

  const calls: ToolCallPreviewInternal[] = beforeEvents.map((event): ToolCallPreviewInternal => {
    const target = event.targetUrl || event.targetDomain;
    return {
      key: event.toolCallId || event.spanId || event.id,
      toolCallId: event.toolCallId,
      spanId: event.spanId,
      parentSpanId: event.parentSpanId,
      status: event.status === "error" ? "error" : "ok",
      how: event.argsPreview || event.summary,
      target,
      targetKey: normalizeTarget(target),
      result: event.resultCode,
      ts: event.ts,
      tsMs: toMs(event.ts),
    };
  });

  if (calls.length === 0) return [];

  const nonBeforeEvents = toolEvents
    .filter((event) => event.name !== "tool.before_tool_call")
    .sort((a, b) => toMs(a.ts) - toMs(b.ts));

  for (const event of nonBeforeEvents) {
    const call = matchEventToCall(event, calls);
    if (!call) continue;

    if (event.status === "error") {
      call.status = "error";
    }
    if (!call.result && event.resultCode) {
      call.result = event.resultCode;
    }
    if (!call.target && (event.targetUrl || event.targetDomain)) {
      call.target = event.targetUrl || event.targetDomain;
      call.targetKey = normalizeTarget(call.target);
    }
    if (!call.how && (event.argsPreview || event.summary)) {
      call.how = event.argsPreview || event.summary;
    }
  }

  return calls;
}

function buildCallsFromFallback(toolEvents: ToolEventLike[]): ToolCallPreviewInternal[] {
  const map = new Map<string, ToolCallPreviewInternal>();
  const sorted = [...toolEvents].sort((a, b) => toMs(a.ts) - toMs(b.ts));

  for (const event of sorted) {
    const target = event.targetUrl || event.targetDomain;
    const fingerprint =
      event.toolCallId ||
      `${normalizeTarget(target)}|${(event.argsPreview || event.summary || "").slice(0, 140)}|${Math.floor(
        toMs(event.ts) / 1500,
      )}`;
    const key = fingerprint || event.spanId || event.id;
    const existing: ToolCallPreviewInternal = map.get(key) || {
      key,
      toolCallId: event.toolCallId,
      spanId: event.spanId,
      parentSpanId: event.parentSpanId,
      status: "ok",
      targetKey: normalizeTarget(target),
      tsMs: toMs(event.ts),
    };

    if (event.status === "error") {
      existing.status = "error";
    }
    if (!existing.how) {
      existing.how = event.argsPreview || event.summary;
    }
    if (!existing.target) {
      existing.target = target;
      existing.targetKey = normalizeTarget(target);
    }
    if (!existing.result) {
      existing.result = event.resultCode;
    }
    if (!existing.ts) {
      existing.ts = event.ts;
    }

    map.set(key, existing);
  }

  return [...map.values()];
}

function buildToolCallGroups(detail: TraceDetail, highlights: TraceHighlights): Array<{
  name: string;
  count: number;
  calls: ToolCallPreview[];
}> {
  const perToolEvents = new Map<string, ToolEventLike[]>();

  for (const event of detail.events) {
    if (event.kind !== "tool") continue;
    if (!event.name.startsWith("tool.")) continue;
    const toolName = (event.toolName || "unknown").trim() || "unknown";
    const bucket = perToolEvents.get(toolName) || [];
    bucket.push(event);
    perToolEvents.set(toolName, bucket);
  }

  const nameOrder = [
    ...highlights.uniqueTools.map((item) => item.name),
    ...[...perToolEvents.keys()].filter((name) => !highlights.uniqueTools.some((item) => item.name === name)),
  ];

  return nameOrder.map((name) => {
    const toolEvents = perToolEvents.get(name) || [];
    const callsRaw = buildCallsFromBeforeEvents(toolEvents);
    const calls: ToolCallPreview[] = (callsRaw.length > 0 ? callsRaw : buildCallsFromFallback(toolEvents))
      .sort((a, b) => a.tsMs - b.tsMs)
      .map((call): ToolCallPreview => ({
        key: call.key,
        status: call.status,
        how: call.how,
        target: call.target,
        result: call.result,
        ts: call.ts,
      }));
    const countFromHighlights = highlights.uniqueTools.find((item) => item.name === name)?.count;
    return {
      name,
      count: calls.length > 0 ? calls.length : countFromHighlights ?? 0,
      calls,
    };
  });
}

export default function TraceOverviewCard({ detail, highlights }: TraceOverviewCardProps) {
  const toolGroups = buildToolCallGroups(detail, highlights);

  return (
    <div className="rounded-lg border border-border bg-muted/20 p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm font-semibold text-foreground">Trace overview</p>
      </div>

      <div className="grid grid-cols-2 gap-x-6 gap-y-3 md:grid-cols-4">
        <Metric label="Trigger" value={detail.triggerType || "-"} />
        <Metric label="Provider" value={detail.messageProvider || "-"} />
        <Metric label="Session kind" value={detail.sessionKind || "-"} />
        <Metric label="Model" value={detail.model || "-"} />
        <Metric label="Tool calls" value={formatNumber(detail.toolCallsCount)} />
        <Metric label="Messages" value={formatNumber(detail.messagesCount)} />
        <Metric label="Context history" value={formatNumber(detail.contextHistoryCount)} />
        <Metric label="Tokens in" value={formatNumber(detail.tokensIn)} />
        <Metric label="Tokens out" value={formatNumber(detail.tokensOut)} />
        <Metric label="Prompt size" value={formatBytes(detail.promptBytes)} />
      </div>

      {detail.triggerReason ? (
        <div className="mt-3 rounded-md border border-border bg-secondary/20 px-3 py-2 text-xs text-muted-foreground">
          Trigger reason: {truncate(detail.triggerReason, 220)}
        </div>
      ) : null}

      <div className="mt-4 space-y-2">
        <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Tools used</p>
        {toolGroups.length === 0 ? (
          <p className="text-xs text-muted-foreground">No tool calls.</p>
        ) : (
          <div className="space-y-2">
            {toolGroups.map((tool) => (
              <details key={tool.name} className="rounded-md border border-border bg-card px-3 py-2">
                <summary className="cursor-pointer list-none">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-medium text-foreground">{tool.name}</span>
                    <span className="text-xs text-muted-foreground">{tool.count} calls</span>
                  </div>
                </summary>

                <div className="mt-2 space-y-2">
                  {tool.calls.slice(0, 12).map((call) => (
                    <div key={call.key} className="rounded-md border border-border bg-secondary/20 px-2 py-2">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="font-mono text-xs text-foreground">
                          {truncate(call.how || call.target || call.result || "call")}
                        </span>
                        <span
                          className={
                            call.status === "error"
                              ? "text-xs font-medium text-destructive"
                              : "text-xs font-medium text-emerald-300"
                          }
                        >
                          {call.status}
                        </span>
                      </div>
                      {call.target ? (
                        <p className="mt-1 font-mono text-xs text-muted-foreground">
                          target: {truncate(call.target, 160)}
                        </p>
                      ) : null}
                    </div>
                  ))}
                  {tool.calls.length > 12 ? (
                    <p className="text-xs text-muted-foreground">+{tool.calls.length - 12} more calls</p>
                  ) : null}
                </div>
              </details>
            ))}
          </div>
        )}
      </div>

      <div className="mt-3 text-xs text-muted-foreground">
        Domains touched:{" "}
        {highlights.externalDomains.length > 0
          ? `${highlights.externalDomains
              .slice(0, 12)
              .map((item) => item.domain)
              .join(", ")}${highlights.externalDomains.length > 12 ? ` (+${highlights.externalDomains.length - 12} more)` : ""}`
          : "-"}
      </div>
    </div>
  );
}
