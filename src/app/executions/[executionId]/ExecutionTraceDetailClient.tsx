/**
 * @fileoverview ClawSight SIEM module: platform/src/app/executions/[executionId]/ExecutionTraceDetailClient.tsx.
 */
"use client";

import { useEffect, useState } from "react";
import TraceDetailPanel from "@/app/traces/_components/TraceDetailPanel";
import { adaptTraceDetail } from "@/lib/traces/adapters";
import type { TraceDetail, TraceMode, TraceTab } from "@/lib/traces/types";

type ExecutionTraceDetailClientProps = {
  executionId: string;
};

function normalizeMode(value: string | null): TraceMode {
  if (value === "raw") return "raw";
  return "narrative";
}

function normalizeTab(value: string | null): TraceTab {
  if (value === "all" || value === "messages" || value === "tools" || value === "policy") return value;
  return "all";
}

export default function ExecutionTraceDetailClient({ executionId }: ExecutionTraceDetailClientProps) {
  const [mode, setMode] = useState<TraceMode>(() =>
    typeof window === "undefined" ? "narrative" : normalizeMode(new URLSearchParams(window.location.search).get("mode")),
  );
  const [tab, setTab] = useState<TraceTab>(() =>
    typeof window === "undefined" ? "all" : normalizeTab(new URLSearchParams(window.location.search).get("tab")),
  );
  const [showInternal, setShowInternal] = useState<boolean>(() =>
    typeof window === "undefined" ? false : new URLSearchParams(window.location.search).get("showInternal") === "1",
  );
  const [query, setQuery] = useState<string>(() =>
    typeof window === "undefined" ? "" : new URLSearchParams(window.location.search).get("traceSearch") || "",
  );
  const [loading, setLoading] = useState(true);
  const [detail, setDetail] = useState<TraceDetail | undefined>(undefined);

  useEffect(() => {
    let cancelled = false;
    fetch(`/api/traces/${encodeURIComponent(executionId)}?spanLimit=800`, { cache: "no-store" })
      .then(async (response) => {
        const json = await response.json();
        if (!response.ok || !json?.trace || !Array.isArray(json?.spans)) {
          throw new Error(json?.error || "Failed to load trace detail");
        }
        return adaptTraceDetail(json.trace, json.spans);
      })
      .then((nextDetail) => {
        if (!cancelled) setDetail(nextDetail);
      })
      .catch(() => {
        if (!cancelled) setDetail(undefined);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [executionId]);

  return (
    <TraceDetailPanel
      detail={detail}
      loading={loading}
      mode={mode}
      tab={tab}
      showInternal={showInternal}
      query={query}
      onModeChange={setMode}
      onTabChange={setTab}
      onShowInternalChange={setShowInternal}
      onQueryChange={setQuery}
    />
  );
}
