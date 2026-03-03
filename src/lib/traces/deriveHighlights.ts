/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/traces/deriveHighlights.ts.
 */
import type { TraceDetail, TraceEvent, TraceHighlights } from "@/lib/traces/types";

function parseDomain(url: string): string | undefined {
  try {
    return new URL(url).hostname || undefined;
  } catch {
    return undefined;
  }
}

function extractErrorMessage(event: TraceEvent): string {
  if (event.summary && event.summary.trim().length > 0) return event.summary.trim();
  if (event.resultCode && event.resultCode.trim().length > 0) return event.resultCode.trim();
  return event.name;
}

function extractUrlsFromText(value?: string): string[] {
  if (!value) return [];
  const matches = value.match(/https?:\/\/[^\s"'`<>]+/gi) || [];
  const cleaned = matches
    .map((item) => item.replace(/[),.;]+$/g, ""))
    .filter((item) => item.length > 0);
  return [...new Set(cleaned)];
}

export function deriveHighlights(detail: TraceDetail): TraceHighlights {
  const beforeToolEvents = detail.events.filter(
    (event) => event.kind === "tool" && event.name === "tool.before_tool_call",
  );
  const toolBasisEvents =
    beforeToolEvents.length > 0
      ? beforeToolEvents
      : detail.events.filter((event) => event.kind === "tool" && event.name === "tool.after_tool_call");

  const toolCounts = new Map<string, number>();
  const domainUrlSets = new Map<string, Set<string>>();
  const errorCounts = new Map<string, { code: string; message: string; count: number; firstAt?: string }>();

  for (const event of toolBasisEvents) {
    if (event.toolName) {
      toolCounts.set(event.toolName, (toolCounts.get(event.toolName) ?? 0) + 1);
    }

    const candidateUrls = new Set<string>();
    if (event.targetUrl) candidateUrls.add(event.targetUrl);
    for (const artifact of event.artifacts || []) {
      if (artifact.url) candidateUrls.add(artifact.url);
    }
    for (const url of extractUrlsFromText(event.argsPreview)) {
      candidateUrls.add(url);
    }
    for (const url of extractUrlsFromText(event.summary)) {
      candidateUrls.add(url);
    }

    if (candidateUrls.size > 0) {
      for (const candidateUrl of candidateUrls) {
        const domain = parseDomain(candidateUrl);
        if (!domain) continue;
        const set = domainUrlSets.get(domain) || new Set<string>();
        set.add(candidateUrl);
        domainUrlSets.set(domain, set);
      }
    } else if (event.targetDomain) {
      const set = domainUrlSets.get(event.targetDomain) || new Set<string>();
      if (event.spanId) {
        set.add(`span:${event.spanId}`);
      } else {
        set.add(`event:${event.id}`);
      }
      domainUrlSets.set(event.targetDomain, set);
    }
  }

  for (const event of detail.events) {
    if (event.status === "error") {
      const code = event.resultCode || "error";
      const message = extractErrorMessage(event);
      const key = `${code}|${message}`;
      const existing = errorCounts.get(key);
      if (existing) {
        existing.count += 1;
      } else {
        errorCounts.set(key, {
          code,
          message,
          count: 1,
          firstAt: event.ts,
        });
      }
    }
  }

  const uniqueTools = [...toolCounts.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));

  const externalDomains = [...domainUrlSets.entries()]
    .map(([domain, urls]) => ({ domain, count: urls.size }))
    .sort((a, b) => b.count - a.count || a.domain.localeCompare(b.domain));

  const errorSummary = [...errorCounts.values()]
    .sort((a, b) => b.count - a.count || a.code.localeCompare(b.code));

  return {
    uniqueTools,
    externalDomains,
    errorSummary,
  };
}
