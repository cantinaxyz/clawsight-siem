-- Trace MVP upgrade:
-- - per-message root identifiers
-- - explicit parent span linkage
-- - orphan trace sink table

ALTER TABLE "TelemetryEvent"
  ADD COLUMN "rootExecutionId" TEXT,
  ADD COLUMN "rootMessageId" TEXT,
  ADD COLUMN "parentSpanId" TEXT;

CREATE INDEX "TelemetryEvent_rootExecutionId_ts_idx"
  ON "TelemetryEvent"("rootExecutionId", "ts" DESC);
CREATE INDEX "TelemetryEvent_rootMessageId_ts_idx"
  ON "TelemetryEvent"("rootMessageId", "ts" DESC);

ALTER TABLE "Trace"
  ADD COLUMN "rootExecutionId" TEXT,
  ADD COLUMN "rootMessageId" TEXT;

CREATE INDEX "Trace_rootExecutionId_lastEventTs_idx"
  ON "Trace"("rootExecutionId", "lastEventTs" DESC);
CREATE INDEX "Trace_rootMessageId_lastEventTs_idx"
  ON "Trace"("rootMessageId", "lastEventTs" DESC);

ALTER TABLE "TraceSpan"
  ADD COLUMN "rootExecutionId" TEXT,
  ADD COLUMN "rootMessageId" TEXT;

CREATE INDEX "TraceSpan_rootExecutionId_ts_idx"
  ON "TraceSpan"("rootExecutionId", "ts" DESC);
CREATE INDEX "TraceSpan_rootMessageId_ts_idx"
  ON "TraceSpan"("rootMessageId", "ts" DESC);

CREATE TABLE "TraceOrphan" (
  "id" SERIAL NOT NULL,
  "eventExternalId" TEXT,
  "eventTs" TIMESTAMP(3),
  "eventCategory" TEXT,
  "eventAction" TEXT,
  "reason" TEXT NOT NULL,
  "traceHint" TEXT,
  "requestId" TEXT,
  "rootExecutionId" TEXT,
  "rootMessageId" TEXT,
  "openclawSessionKey" TEXT,
  "payload" JSONB,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "TraceOrphan_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "TraceOrphan_createdAt_idx"
  ON "TraceOrphan"("createdAt" DESC);
CREATE INDEX "TraceOrphan_reason_createdAt_idx"
  ON "TraceOrphan"("reason", "createdAt" DESC);
CREATE INDEX "TraceOrphan_requestId_createdAt_idx"
  ON "TraceOrphan"("requestId", "createdAt" DESC);
CREATE INDEX "TraceOrphan_rootExecutionId_createdAt_idx"
  ON "TraceOrphan"("rootExecutionId", "createdAt" DESC);
CREATE INDEX "TraceOrphan_rootMessageId_createdAt_idx"
  ON "TraceOrphan"("rootMessageId", "createdAt" DESC);
CREATE INDEX "TraceOrphan_openclawSessionKey_createdAt_idx"
  ON "TraceOrphan"("openclawSessionKey", "createdAt" DESC);
