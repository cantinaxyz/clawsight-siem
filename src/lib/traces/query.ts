/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/traces/query.ts.
 */
export type TraceListFilterInput = {
  sourceType?: string;
  status?: string;
  agentKey?: string;
  search?: string;
  includeSystem?: boolean;
  limit: number;
};

export type TraceRecord = {
  traceId: string;
  sourceType: string;
  status: string;
  startedAt: Date;
  endedAt: Date | null;
  durationMs: number | null;
  lastEventTs: Date;
  spanCount: number;
  eventCount: number;
  errorCount: number;
  warnCount: number;
  blockCount: number;
  maxRiskScore: number | null;
  firstCategory: string | null;
  firstAction: string | null;
  projectId: string | null;
  agentInstanceId: string | null;
  requestId: string | null;
  openclawAgentId: string | null;
  openclawSessionKey: string | null;
  openclawSessionId: string | null;
  openclawRunId: string | null;
  createdAt: Date;
  updatedAt: Date;
};

export type TraceSpanRecord = {
  id: number;
  traceId: string;
  spanId: string;
  parentSpanId: string | null;
  eventExternalId: string | null;
  ts: Date;
  stage: string;
  sourceType: string;
  status: string;
  category: string;
  action: string;
  severity: string;
  outcome: string | null;
  outcomeReason: string | null;
  durationMs: number | null;
  latencyMs: number | null;
  errorClass: string | null;
  errorCode: string | null;
  toolName: string | null;
  requestId: string | null;
  sessionKey: string | null;
  sessionId: string | null;
  runId: string | null;
  openclawAgentId: string | null;
  riskScore: number | null;
  payloadSummary: unknown;
  payload: unknown;
  payloadRedacted: unknown;
  createdAt: Date;
  updatedAt: Date;
};

export type SerializedTrace = Omit<
  TraceRecord,
  "startedAt" | "endedAt" | "lastEventTs" | "createdAt" | "updatedAt"
> & {
  startedAt: number;
  endedAt: number | null;
  lastEventTs: number;
  createdAt: number;
  updatedAt: number;
};

export type SerializedTraceSpan = Omit<TraceSpanRecord, "ts" | "createdAt" | "updatedAt"> & {
  ts: number;
  createdAt: number;
  updatedAt: number;
};

export type TraceOrphanRecord = {
  id: number;
  eventExternalId: string | null;
  eventTs: Date | null;
  eventCategory: string | null;
  eventAction: string | null;
  reason: string;
  traceHint: string | null;
  requestId: string | null;
  rootExecutionId: string | null;
  rootMessageId: string | null;
  openclawSessionKey: string | null;
  payload: unknown;
  createdAt: Date;
  updatedAt: Date;
};

export type SerializedTraceOrphan = Omit<
  TraceOrphanRecord,
  "eventTs" | "createdAt" | "updatedAt"
> & {
  eventTs: number | null;
  createdAt: number;
  updatedAt: number;
};

export function parsePositiveInt(value: string | null, fallback: number, max = 300): number {
  if (!value) return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) return fallback;
  return Math.min(parsed, max);
}

export function parseTraceFiltersFromUrl(url: URL): TraceListFilterInput {
  const q = url.searchParams;
  const search = q.get("search")?.trim() || q.get("q")?.trim() || undefined;
  return {
    sourceType: q.get("sourceType")?.trim() || undefined,
    status: q.get("status")?.trim() || undefined,
    agentKey: q.get("agentKey")?.trim() || undefined,
    search: search && search.length > 0 ? search : undefined,
    includeSystem: q.get("includeSystem") === "1",
    limit: parsePositiveInt(q.get("limit"), 80),
  };
}

export function serializeTraceRecord(row: TraceRecord): SerializedTrace {
  return {
    ...row,
    startedAt: row.startedAt.getTime(),
    endedAt: row.endedAt ? row.endedAt.getTime() : null,
    lastEventTs: row.lastEventTs.getTime(),
    createdAt: row.createdAt.getTime(),
    updatedAt: row.updatedAt.getTime(),
  };
}

export function serializeTraceSpanRecord(row: TraceSpanRecord): SerializedTraceSpan {
  return {
    ...row,
    payload: row.payloadRedacted ?? row.payloadSummary ?? null,
    ts: row.ts.getTime(),
    createdAt: row.createdAt.getTime(),
    updatedAt: row.updatedAt.getTime(),
  };
}

export function serializeTraceOrphanRecord(row: TraceOrphanRecord): SerializedTraceOrphan {
  return {
    ...row,
    payload: null,
    eventTs: row.eventTs ? row.eventTs.getTime() : null,
    createdAt: row.createdAt.getTime(),
    updatedAt: row.updatedAt.getTime(),
  };
}
