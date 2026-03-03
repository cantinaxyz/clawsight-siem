/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/executions/api.ts.
 */
"use client";

import type { Execution, ExecutionLineageNode } from "@/lib/executions/types";

export async function fetchExecutions(input?: {
  search?: string;
  triggerType?: string;
  outcome?: string;
  agentKey?: string;
  limit?: number;
}): Promise<Execution[]> {
  const params = new URLSearchParams();
  if (input?.search) params.set("search", input.search);
  if (input?.triggerType) params.set("triggerType", input.triggerType);
  if (input?.outcome) params.set("outcome", input.outcome);
  if (input?.agentKey) params.set("agentKey", input.agentKey);
  if (input?.limit) params.set("limit", String(input.limit));

  const query = params.toString();
  const response = await fetch(`/api/executions${query ? `?${query}` : ""}`, {
    cache: "no-store",
  });
  const json = await response.json();
  if (!response.ok || !json?.ok || !Array.isArray(json?.data)) {
    throw new Error(json?.error || "Failed to fetch executions");
  }
  return json.data as Execution[];
}

export async function fetchExecutionLineage(executionId: string): Promise<ExecutionLineageNode | null> {
  const response = await fetch(`/api/executions/${encodeURIComponent(executionId)}/lineage`, {
    cache: "no-store",
  });
  const json = await response.json();
  if (response.status === 404) return null;
  if (!response.ok || !json?.ok) {
    throw new Error(json?.error || "Failed to fetch execution lineage");
  }
  return (json.data as ExecutionLineageNode) || null;
}
