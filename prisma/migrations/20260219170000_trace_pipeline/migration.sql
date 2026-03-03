-- Trace pipeline: canonical run traces + span timeline

CREATE TABLE "Trace" (
    "traceId" TEXT NOT NULL,
    "sourceType" TEXT NOT NULL DEFAULT 'user',
    "status" TEXT NOT NULL DEFAULT 'running',
    "startedAt" TIMESTAMP(3) NOT NULL,
    "endedAt" TIMESTAMP(3),
    "durationMs" INTEGER,
    "lastEventTs" TIMESTAMP(3) NOT NULL,
    "spanCount" INTEGER NOT NULL DEFAULT 0,
    "eventCount" INTEGER NOT NULL DEFAULT 0,
    "errorCount" INTEGER NOT NULL DEFAULT 0,
    "warnCount" INTEGER NOT NULL DEFAULT 0,
    "blockCount" INTEGER NOT NULL DEFAULT 0,
    "maxRiskScore" INTEGER,
    "firstCategory" TEXT,
    "firstAction" TEXT,
    "projectId" TEXT,
    "agentInstanceId" TEXT,
    "requestId" TEXT,
    "openclawAgentId" TEXT,
    "openclawSessionKey" TEXT,
    "openclawSessionId" TEXT,
    "openclawRunId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Trace_pkey" PRIMARY KEY ("traceId")
);

CREATE INDEX "Trace_lastEventTs_idx"
  ON "Trace"("lastEventTs" DESC);
CREATE INDEX "Trace_sourceType_lastEventTs_idx"
  ON "Trace"("sourceType", "lastEventTs" DESC);
CREATE INDEX "Trace_status_lastEventTs_idx"
  ON "Trace"("status", "lastEventTs" DESC);
CREATE INDEX "Trace_openclawSessionKey_lastEventTs_idx"
  ON "Trace"("openclawSessionKey", "lastEventTs" DESC);
CREATE INDEX "Trace_openclawRunId_idx" ON "Trace"("openclawRunId");
CREATE INDEX "Trace_requestId_idx" ON "Trace"("requestId");

CREATE TABLE "TraceSpan" (
    "id" SERIAL NOT NULL,
    "traceId" TEXT NOT NULL,
    "spanId" TEXT NOT NULL,
    "parentSpanId" TEXT,
    "eventExternalId" TEXT,
    "ts" TIMESTAMP(3) NOT NULL,
    "stage" TEXT NOT NULL,
    "sourceType" TEXT NOT NULL DEFAULT 'user',
    "status" TEXT NOT NULL DEFAULT 'info',
    "category" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "severity" TEXT NOT NULL DEFAULT 'info',
    "outcome" TEXT,
    "outcomeReason" TEXT,
    "durationMs" INTEGER,
    "latencyMs" INTEGER,
    "errorClass" TEXT,
    "errorCode" TEXT,
    "toolName" TEXT,
    "requestId" TEXT,
    "sessionKey" TEXT,
    "sessionId" TEXT,
    "runId" TEXT,
    "openclawAgentId" TEXT,
    "riskScore" INTEGER,
    "payloadSummary" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "TraceSpan_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "TraceSpan_spanId_key" ON "TraceSpan"("spanId");
CREATE INDEX "TraceSpan_traceId_ts_idx" ON "TraceSpan"("traceId", "ts" ASC);
CREATE INDEX "TraceSpan_stage_ts_idx" ON "TraceSpan"("stage", "ts" DESC);
CREATE INDEX "TraceSpan_sourceType_ts_idx" ON "TraceSpan"("sourceType", "ts" DESC);
CREATE INDEX "TraceSpan_status_ts_idx" ON "TraceSpan"("status", "ts" DESC);
CREATE INDEX "TraceSpan_requestId_ts_idx" ON "TraceSpan"("requestId", "ts" DESC);
CREATE INDEX "TraceSpan_runId_ts_idx" ON "TraceSpan"("runId", "ts" DESC);

ALTER TABLE "TraceSpan"
  ADD CONSTRAINT "TraceSpan_traceId_fkey"
  FOREIGN KEY ("traceId") REFERENCES "Trace"("traceId")
  ON DELETE CASCADE ON UPDATE CASCADE;

CREATE INDEX "TelemetryEvent_traceId_ts_idx"
  ON "TelemetryEvent"("traceId", "ts" DESC);
CREATE INDEX "TelemetryEvent_openclawRunId_ts_idx"
  ON "TelemetryEvent"("openclawRunId", "ts" DESC);
