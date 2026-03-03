/**
 * @fileoverview ClawSight SIEM module: platform/src/components/dashboard/dashboard-live-refresh.tsx.
 */
"use client";

import { useEffect, useRef, useTransition } from "react";
import { useRouter } from "next/navigation";

type DashboardLiveRefreshProps = {
  minRefreshMs?: number;
};

export function DashboardLiveRefresh({ minRefreshMs = 2000 }: DashboardLiveRefreshProps) {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();
  const pendingRef = useRef(false);
  const lastRefreshAtRef = useRef(0);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    pendingRef.current = isPending;
  }, [isPending]);

  useEffect(() => {
    const params = new URLSearchParams();
    params.set("cursorTs", String(Date.now()));
    params.set("limit", "1");
    const source = new EventSource(`/api/telemetry/events/stream?${params.toString()}`);

    const scheduleRefresh = () => {
      const now = Date.now();
      const sinceLast = now - lastRefreshAtRef.current;
      const delay = Math.max(0, minRefreshMs - sinceLast);

      if (timerRef.current) return;
      timerRef.current = setTimeout(() => {
        timerRef.current = null;
        lastRefreshAtRef.current = Date.now();
        startTransition(() => {
          router.refresh();
        });
      }, delay);
    };

    const onTelemetry = () => {
      if (pendingRef.current) return;
      scheduleRefresh();
    };

    source.addEventListener("telemetry", onTelemetry);

    return () => {
      source.removeEventListener("telemetry", onTelemetry);
      source.close();
      if (timerRef.current) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
    };
  }, [minRefreshMs, router]);

  return null;
}
