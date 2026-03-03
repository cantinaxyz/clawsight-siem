/**
 * @fileoverview ClawSight SIEM module: platform/src/app/traces/_components/TraceDetailPanel.tsx.
 */
"use client";

import { useEffect, useMemo, useState } from "react";
import { GitBranch } from "lucide-react";
import DetailModeToolbar from "@/app/traces/_components/DetailModeToolbar";
import ExecutionTimeline from "@/app/traces/_components/ExecutionTimeline";
import TraceOverviewCard from "@/app/traces/_components/TraceOverviewCard";
import { deriveHighlights } from "@/lib/traces/deriveHighlights";
import type { TraceDetail, TraceMode, TraceTab } from "@/lib/traces/types";

type IntentExecutionPayload = {
  execution: {
    executionKey: string;
    rootExecutionId: string;
    agentInstanceId: string | null;
    taskBoundary: string | null;
    expectedScopes: string[];
    expectedDomains: string[];
    driftScore: number;
    extractionMethod: string | null;
    confidence: number | null;
    baselinePatched: boolean;
    baselineVersion: number;
    baselinePatchedAt: string | null;
    baselinePatchedBy: string | null;
    baselinePatchReason: string | null;
  } | null;
  decisions: Array<{
    id: number;
    phase: string;
    action: string;
    scoreDelta: number;
    driftScore: number;
    confidence: number | null;
    reason: string | null;
    toolName: string | null;
    targetDomain: string | null;
    createdAt: string;
    signals?: string[] | null;
    details?: unknown;
  }>;
};

type TraceDetailPanelProps = {
  detail?: TraceDetail;
  loading: boolean;
  mode: TraceMode;
  tab: TraceTab;
  showInternal: boolean;
  query: string;
  onModeChange: (mode: TraceMode) => void;
  onTabChange: (tab: TraceTab) => void;
  onShowInternalChange: (next: boolean) => void;
  onQueryChange: (value: string) => void;
};

function formatTime(value?: string): string {
  if (!value) return "-";
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return "-";
  return date.toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

function formatDuration(durationMs?: number): string {
  if (durationMs == null || !Number.isFinite(durationMs)) return "-";
  if (durationMs < 1000) return `${durationMs}ms`;
  return `${(durationMs / 1000).toFixed(1)}s`;
}

function runStatusClass(status: TraceDetail["runStatus"]): string {
  if (status === "completed") return "text-emerald-300";
  if (status === "failed") return "text-destructive";
  return "text-primary";
}

export default function TraceDetailPanel({
  detail,
  loading,
  mode,
  tab,
  showInternal,
  query,
  onModeChange,
  onTabChange,
  onShowInternalChange,
  onQueryChange,
}: TraceDetailPanelProps) {
  const [intentData, setIntentData] = useState<IntentExecutionPayload | null>(null);
  const [intentLoading, setIntentLoading] = useState(false);
  const [patchOpen, setPatchOpen] = useState(false);
  const [patchSaving, setPatchSaving] = useState(false);
  const [patchError, setPatchError] = useState<string | null>(null);
  const [patchBoundary, setPatchBoundary] = useState("");
  const [patchScopes, setPatchScopes] = useState("");
  const [patchDomains, setPatchDomains] = useState("");
  const [patchRecompute, setPatchRecompute] = useState(false);

  useEffect(() => {
    if (!detail?.traceId) return;
    let cancelled = false;
    setIntentLoading(true);
    fetch(`/api/intent/executions/by-root/${encodeURIComponent(detail.traceId)}`, { cache: "no-store" })
      .then(async (response) => {
        const json = (await response.json()) as IntentExecutionPayload;
        if (!response.ok) throw new Error("Failed to load intent baseline");
        return json;
      })
      .then((json) => {
        if (cancelled) return;
        setIntentData(json);
      })
      .catch(() => {
        if (cancelled) return;
        setIntentData(null);
      })
      .finally(() => {
        if (cancelled) return;
        setIntentLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [detail?.traceId]);

  useEffect(() => {
    const execution = intentData?.execution;
    if (!execution) return;
    setPatchBoundary(execution.taskBoundary || "");
    setPatchScopes(execution.expectedScopes.join(", "));
    setPatchDomains(execution.expectedDomains.join(", "));
  }, [intentData?.execution]);

  const highlights = useMemo(
    () =>
      detail
        ? deriveHighlights(detail)
        : { uniqueTools: [], externalDomains: [], errorSummary: [] },
    [detail],
  );
  const intentExecution = intentData?.execution;
  const recentIntentDecisions = useMemo(
    () => (intentData?.decisions || []).slice(-8),
    [intentData?.decisions],
  );

  if (!detail) {
    return (
      <div className="flex h-64 items-center justify-center rounded-lg border border-border bg-card text-muted-foreground">
        <p className="text-sm">Select a trace to view its timeline</p>
      </div>
    );
  }

  async function submitBaselinePatch() {
    if (!detail?.traceId || !intentExecution) return;
    setPatchSaving(true);
    setPatchError(null);
    try {
      const response = await fetch(`/api/intent/executions/by-root/${encodeURIComponent(detail.traceId)}`, {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          taskBoundary: patchBoundary.trim(),
          expectedScopes: patchScopes
            .split(/[,\n]/)
            .map((item) => item.trim())
            .filter(Boolean),
          expectedDomains: patchDomains
            .split(/[,\n]/)
            .map((item) => item.trim())
            .filter(Boolean),
          patchedBy: "ui.operator",
          reason: "manual baseline patch",
          recompute: patchRecompute,
        }),
      });
      const json = (await response.json()) as { execution?: IntentExecutionPayload["execution"]; error?: string };
      if (!response.ok || !json.execution) {
        throw new Error(json.error || "Failed to patch baseline");
      }
      setIntentData((prev) => ({
        execution: json.execution || null,
        decisions: prev?.decisions || [],
      }));
      setPatchOpen(false);
    } catch (err) {
      setPatchError(String(err));
    } finally {
      setPatchSaving(false);
    }
  }

  return (
    <div className="flex-1 rounded-lg border border-border bg-card">
      <div className="border-b border-border p-4">
        <div className="flex items-center gap-3">
          <GitBranch className="h-5 w-5 text-primary" />
          <div className="min-w-0">
            <h2 className="truncate font-mono text-sm font-semibold text-foreground">{detail.traceId}</h2>
            <p className="truncate text-xs text-muted-foreground">{detail.requestKey || "-"}</p>
          </div>
        </div>

        <div className="mt-3 grid grid-cols-2 gap-3 text-xs md:grid-cols-7">
          <div>
            <span className="text-muted-foreground">Start</span>
            <p className="font-mono text-foreground">{formatTime(detail.startedAt)}</p>
          </div>
          <div>
            <span className="text-muted-foreground">End</span>
            <p className="font-mono text-foreground">{formatTime(detail.endedAt)}</p>
          </div>
          <div>
            <span className="text-muted-foreground">Events</span>
            <p className="text-foreground">{detail.events.length}</p>
          </div>
          <div>
            <span className="text-muted-foreground">Duration</span>
            <p className="text-foreground">{formatDuration(detail.durationMs)}</p>
          </div>
          <div>
            <span className="text-muted-foreground">Run status</span>
            <p className={runStatusClass(detail.runStatus)}>{detail.runStatus}</p>
          </div>
          <div>
            <span className="text-muted-foreground">Errors</span>
            <p className="text-foreground">{detail.errorCount}</p>
          </div>
          <div>
            <span className="text-muted-foreground">Policy blocks</span>
            <p className="text-amber-300">{detail.blockCount}</p>
          </div>
        </div>
      </div>

      <div className="space-y-4 p-4">
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold text-foreground">Intent baseline</h3>
              <p className="text-xs text-muted-foreground">
                Expected scopes/domains and per-decision drift contributions for this execution.
              </p>
            </div>
            {intentExecution ? (
              <button
                type="button"
                onClick={() => setPatchOpen((prev) => !prev)}
                className="rounded-md border border-border px-2 py-1 text-xs text-foreground hover:bg-secondary"
              >
                {patchOpen ? "Close patch" : "Patch baseline"}
              </button>
            ) : null}
          </div>

          {intentLoading ? (
            <p className="mt-3 text-xs text-muted-foreground">Loading baseline…</p>
          ) : null}

          {!intentLoading && !intentExecution ? (
            <p className="mt-3 text-xs text-muted-foreground">No execution baseline found for this trace.</p>
          ) : null}

          {intentExecution ? (
            <>
              <div className="mt-3 grid grid-cols-2 gap-3 text-xs md:grid-cols-6">
                <div>
                  <p className="text-muted-foreground">Extraction</p>
                  <p className="text-foreground">{intentExecution.extractionMethod || "-"}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">Confidence</p>
                  <p className="text-foreground">{intentExecution.confidence ?? "-"}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">Drift</p>
                  <p className="text-foreground">{intentExecution.driftScore}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">Baseline version</p>
                  <p className="text-foreground">{intentExecution.baselineVersion}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">Patched</p>
                  <p className="text-foreground">{intentExecution.baselinePatched ? "yes" : "no"}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">Execution key</p>
                  <p className="truncate font-mono text-foreground">{intentExecution.executionKey}</p>
                </div>
              </div>

              <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-2">
                <div className="rounded-md border border-border bg-secondary/20 p-3">
                  <p className="text-xs text-muted-foreground">Task boundary</p>
                  <p className="mt-1 text-sm text-foreground">{intentExecution.taskBoundary || "-"}</p>
                </div>
                <div className="rounded-md border border-border bg-secondary/20 p-3">
                  <p className="text-xs text-muted-foreground">Expected scopes</p>
                  <p className="mt-1 text-sm text-foreground">{intentExecution.expectedScopes.join(", ") || "-"}</p>
                  <p className="mt-2 text-xs text-muted-foreground">Expected domains</p>
                  <p className="mt-1 text-sm text-foreground">{intentExecution.expectedDomains.join(", ") || "-"}</p>
                </div>
              </div>

              {patchOpen ? (
                <div className="mt-3 rounded-md border border-border bg-secondary/20 p-3">
                  <h4 className="text-sm font-medium text-foreground">Patch baseline</h4>
                  <div className="mt-2 grid grid-cols-1 gap-2">
                    <textarea
                      value={patchBoundary}
                      onChange={(event) => setPatchBoundary(event.target.value)}
                      className="h-20 rounded-md border border-input bg-background p-2 text-xs text-foreground"
                    />
                    <input
                      value={patchScopes}
                      onChange={(event) => setPatchScopes(event.target.value)}
                      className="h-9 rounded-md border border-input bg-background px-2 text-xs text-foreground"
                      placeholder="filesystem_read, network_read"
                    />
                    <input
                      value={patchDomains}
                      onChange={(event) => setPatchDomains(event.target.value)}
                      className="h-9 rounded-md border border-input bg-background px-2 text-xs text-foreground"
                      placeholder="finance, finance.yahoo.com"
                    />
                    <label className="inline-flex items-center gap-2 text-xs text-foreground">
                      <input
                        type="checkbox"
                        checked={patchRecompute}
                        onChange={(event) => setPatchRecompute(event.target.checked)}
                        className="h-4 w-4 rounded border-border bg-secondary"
                      />
                      Recompute by resetting drift/status for this execution
                    </label>
                    {patchError ? <p className="text-xs text-destructive">{patchError}</p> : null}
                    <div className="flex justify-end">
                      <button
                        type="button"
                        onClick={submitBaselinePatch}
                        disabled={patchSaving}
                        className="rounded-md border border-border px-3 py-1 text-xs text-foreground hover:bg-secondary disabled:opacity-60"
                      >
                        {patchSaving ? "Saving..." : "Save patch"}
                      </button>
                    </div>
                  </div>
                </div>
              ) : null}

              {recentIntentDecisions.length > 0 ? (
                <div className="mt-3 overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead className="text-muted-foreground">
                      <tr className="border-b border-border">
                        <th className="px-2 py-1 text-left">Time</th>
                        <th className="px-2 py-1 text-left">Stage</th>
                        <th className="px-2 py-1 text-left">Tool/Policy</th>
                        <th className="px-2 py-1 text-left">Decision</th>
                        <th className="px-2 py-1 text-left">Delta</th>
                        <th className="px-2 py-1 text-left">Drift</th>
                        <th className="px-2 py-1 text-left">Reason</th>
                      </tr>
                    </thead>
                    <tbody>
                      {recentIntentDecisions.map((row) => (
                        <tr key={row.id} className="border-b border-border/50">
                          <td className="px-2 py-1 text-muted-foreground">{formatTime(row.createdAt)}</td>
                          <td className="px-2 py-1 text-foreground">{row.phase}</td>
                          <td className="px-2 py-1 text-foreground">{row.toolName || "policy"}</td>
                          <td className="px-2 py-1 text-foreground">{row.action}</td>
                          <td className="px-2 py-1 text-foreground">{row.scoreDelta >= 0 ? `+${row.scoreDelta}` : row.scoreDelta}</td>
                          <td className="px-2 py-1 text-foreground">{row.driftScore}</td>
                          <td className="px-2 py-1 text-muted-foreground">{row.reason || "-"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : null}
            </>
          ) : null}
        </div>

        <TraceOverviewCard detail={detail} highlights={highlights} />

        <DetailModeToolbar
          mode={mode}
          tab={tab}
          showInternal={showInternal}
          query={query}
          onModeChange={onModeChange}
          onTabChange={onTabChange}
          onShowInternalChange={onShowInternalChange}
          onQueryChange={onQueryChange}
        />

        {loading ? (
          <div className="rounded-lg border border-border bg-card p-4 text-sm text-muted-foreground">Loading trace…</div>
        ) : null}

        <ExecutionTimeline detail={detail} mode={mode} tab={tab} showInternal={showInternal} query={query} />
      </div>
    </div>
  );
}
