/**
 * @fileoverview ClawSight SIEM module: platform/src/app/traces/_components/TraceWorkbench.tsx.
 */
"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { usePathname, useSearchParams } from "next/navigation";
import TraceDetailPanel from "@/app/traces/_components/TraceDetailPanel";
import TraceList from "@/app/traces/_components/TraceList";
import { adaptTraceDetail } from "@/lib/traces/adapters";
import type { TraceDetail, TraceMode, TraceSummary, TraceTab } from "@/lib/traces/types";

type TraceWorkbenchProps = {
  initialTraces: TraceSummary[];
  initialTotal: number;
  initialDetail?: TraceDetail;
  initialSelectedTraceId?: string;
};

function normalizeMode(value: string | null): TraceMode {
  if (value === "raw") return "raw";
  return "narrative";
}

function normalizeTab(value: string | null): TraceTab {
  if (value === "all" || value === "messages" || value === "tools" || value === "policy") return value;
  return "all";
}

export default function TraceWorkbench({
  initialTraces,
  initialTotal,
  initialDetail,
  initialSelectedTraceId,
}: TraceWorkbenchProps) {
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const [selectedTraceId, setSelectedTraceId] = useState<string | undefined>(
    initialSelectedTraceId || initialTraces[0]?.traceId,
  );
  const [loading, setLoading] = useState(false);

  const [mode, setMode] = useState<TraceMode>(() => normalizeMode(searchParams.get("mode")));
  const [tab, setTab] = useState<TraceTab>(() => normalizeTab(searchParams.get("tab")));
  const [showInternal, setShowInternal] = useState(searchParams.get("showInternal") === "1");
  const [query, setQuery] = useState(searchParams.get("traceSearch") || "");

  const detailCacheRef = useRef<Record<string, TraceDetail>>(
    initialDetail ? { [initialDetail.traceId]: initialDetail } : {},
  );
  const [detail, setDetail] = useState<TraceDetail | undefined>(initialDetail);

  const summariesById = useMemo(
    () => new Map(initialTraces.map((summary) => [summary.traceId, summary])),
    [initialTraces],
  );

  useEffect(() => {
    if (!selectedTraceId && initialTraces.length > 0) {
      setSelectedTraceId(initialTraces[0].traceId);
      return;
    }
    if (selectedTraceId && !summariesById.has(selectedTraceId)) {
      setSelectedTraceId(initialTraces[0]?.traceId);
    }
  }, [selectedTraceId, initialTraces, summariesById]);

  useEffect(() => {
    let cancelled = false;

    async function loadTrace(traceId: string) {
      const cached = detailCacheRef.current[traceId];
      if (cached) {
        setDetail(cached);
        return;
      }

      setLoading(true);
      try {
        const response = await fetch(`/api/traces/${encodeURIComponent(traceId)}?spanLimit=800`, {
          cache: "no-store",
        });
        const json = await response.json();
        if (!response.ok || !json?.trace || !Array.isArray(json?.spans)) {
          throw new Error(json?.error || `Failed to load trace ${traceId}`);
        }
        const nextDetail = adaptTraceDetail(json.trace, json.spans);
        if (cancelled) return;
        detailCacheRef.current[traceId] = nextDetail;
        setDetail(nextDetail);
      } catch {
        if (!cancelled) {
          setDetail(undefined);
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    if (selectedTraceId) {
      void loadTrace(selectedTraceId);
    } else {
      setDetail(undefined);
    }

    return () => {
      cancelled = true;
    };
  }, [selectedTraceId]);

  function replaceQuery(next: Record<string, string | undefined>) {
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    for (const [key, value] of Object.entries(next)) {
      if (value == null || value.length === 0) {
        params.delete(key);
      } else {
        params.set(key, value);
      }
    }
    const queryString = params.toString();
    window.history.replaceState(window.history.state, "", queryString ? `${pathname}?${queryString}` : pathname);
  }

  function handleSelectTrace(traceId: string) {
    setSelectedTraceId(traceId);
    replaceQuery({ traceId });
  }

  function handleModeChange(next: TraceMode) {
    setMode(next);
    replaceQuery({ mode: next });
  }

  function handleTabChange(next: TraceTab) {
    setTab(next);
    replaceQuery({ tab: next });
  }

  function handleInternalChange(next: boolean) {
    setShowInternal(next);
    replaceQuery({ showInternal: next ? "1" : undefined });
  }

  function handleQueryChange(value: string) {
    setQuery(value);
  }

  return (
    <div className="flex flex-col gap-6 xl:flex-row">
      <TraceList
        traces={initialTraces}
        selectedTraceId={selectedTraceId}
        total={initialTotal}
        onSelectTrace={handleSelectTrace}
      />

      <TraceDetailPanel
        detail={detail}
        loading={loading}
        mode={mode}
        tab={tab}
        showInternal={showInternal}
        query={query}
        onModeChange={handleModeChange}
        onTabChange={handleTabChange}
        onShowInternalChange={handleInternalChange}
        onQueryChange={handleQueryChange}
      />
    </div>
  );
}
