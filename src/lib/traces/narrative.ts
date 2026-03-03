/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/traces/narrative.ts.
 */
import type { TraceRunSummary } from "@/lib/traces/summary";

function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value < 0) return "0B";
  if (value < 1024) return `${Math.round(value)}B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)}KB`;
  return `${(value / (1024 * 1024)).toFixed(1)}MB`;
}

export function buildTraceNarrative(summary: TraceRunSummary): string[] {
  const lines: string[] = [];

  lines.push("User input was received and mapped to this execution trace.");

  if (summary.inputArtifacts.length > 0) {
    const topArtifacts = summary.inputArtifacts
      .slice(0, 3)
      .map((item) => item.fileName ?? item.filePath ?? item.url ?? item.label)
      .filter(Boolean)
      .join(", ");
    lines.push(
      `Input artifacts detected (${summary.inputArtifacts.length}): ${topArtifacts}${summary.inputArtifacts.length > 3 ? ", ..." : ""}.`,
    );
  }

  const prepParts: string[] = [];
  if (summary.provider || summary.model) {
    prepParts.push(`model ${summary.provider ?? "unknown"}/${summary.model ?? "unknown"}`);
  }
  if (typeof summary.contextHistoryCount === "number") {
    prepParts.push(`history ${summary.contextHistoryCount} messages`);
  }
  if (typeof summary.promptLen === "number") {
    prepParts.push(`prompt ${formatBytes(summary.promptLen)}`);
  }
  lines.push(
    prepParts.length > 0
      ? `Model preparation completed with ${prepParts.join(", ")}.`
      : "Model preparation completed.",
  );

  if (summary.toolCallCount > 0) {
    const toolNames = summary.toolsUsed.slice(0, 3).map((item) => `${item.tool} (${item.count})`).join(", ");
    const retryText = summary.retries > 0 ? ` with ${summary.retries} retry${summary.retries === 1 ? "" : "ies"}` : "";
    const failureText = summary.toolErrorCount > 0 ? `; ${summary.toolErrorCount} failed` : "";
    lines.push(
      `Agent executed ${summary.toolCallCount} tool call${summary.toolCallCount === 1 ? "" : "s"}${retryText}${failureText}.${toolNames ? ` Tools: ${toolNames}.` : ""}`,
    );
  } else {
    lines.push("Agent completed without external tool calls.");
  }

  if (summary.visitedUrls.length > 0) {
    const top = summary.visitedUrls.slice(0, 3).join(", ");
    lines.push(`Visited URLs (${summary.visitedUrls.length}): ${top}${summary.visitedUrls.length > 3 ? ", ..." : ""}.`);
  }

  const responseParts: string[] = [];
  if (typeof summary.finalAssistantMessageLength === "number") {
    responseParts.push(`length ${summary.finalAssistantMessageLength}`);
  }
  if (typeof summary.tokensIn === "number" || typeof summary.tokensOut === "number") {
    responseParts.push(`tokens in ${summary.tokensIn ?? "-"} / out ${summary.tokensOut ?? "-"}`);
  }
  lines.push(
    responseParts.length > 0
      ? `Assistant response generated (${responseParts.join(", ")}).`
      : "Assistant response generated.",
  );

  if (summary.issues.length > 0) {
    lines.push(`Run completed with outcome ${summary.finalOutcome}; ${summary.issues.length} execution issue${summary.issues.length === 1 ? "" : "s"} detected.`);
  } else {
    lines.push(`Run completed with outcome ${summary.finalOutcome}.`);
  }

  return lines;
}
