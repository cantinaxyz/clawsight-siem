ALTER TABLE "ThreatAlert"
  ADD COLUMN IF NOT EXISTS "alertModel" TEXT NOT NULL DEFAULT 'execution_v2',
  ADD COLUMN IF NOT EXISTS "executionCategory" TEXT,
  ADD COLUMN IF NOT EXISTS "breachLevel" TEXT,
  ADD COLUMN IF NOT EXISTS "rootExecutionId" TEXT,
  ADD COLUMN IF NOT EXISTS "rollup" JSONB;

UPDATE "ThreatAlert"
SET "alertModel" = 'legacy_event_v1'
WHERE COALESCE("executionCategory", '') = ''
  AND "rollup" IS NULL;

CREATE INDEX IF NOT EXISTS "ThreatAlert_rootExecutionId_ts_idx"
  ON "ThreatAlert"("rootExecutionId", "ts" DESC);

CREATE INDEX IF NOT EXISTS "ThreatAlert_alertModel_status_ts_idx"
  ON "ThreatAlert"("alertModel", "status", "ts" DESC);

CREATE INDEX IF NOT EXISTS "ThreatAlert_executionCategory_breachLevel_ts_idx"
  ON "ThreatAlert"("executionCategory", "breachLevel", "ts" DESC);

CREATE TABLE IF NOT EXISTS "ExecutionRiskState" (
  "id" SERIAL PRIMARY KEY,
  "executionId" TEXT NOT NULL,
  "rootExecutionId" TEXT,
  "projectId" TEXT,
  "agentInstanceId" TEXT,
  "openclawAgentId" TEXT,
  "triggerType" TEXT,
  "category" TEXT NOT NULL,
  "status" TEXT NOT NULL DEFAULT 'normal',
  "maxSeverity" TEXT NOT NULL DEFAULT 'low',
  "driftScore" INTEGER,
  "blockCount" INTEGER NOT NULL DEFAULT 0,
  "warnCount" INTEGER NOT NULL DEFAULT 0,
  "modifyCount" INTEGER NOT NULL DEFAULT 0,
  "errorCount" INTEGER NOT NULL DEFAULT 0,
  "sanitizationCount" INTEGER NOT NULL DEFAULT 0,
  "signalCount" INTEGER NOT NULL DEFAULT 0,
  "firstSignalAt" TIMESTAMP(3) NOT NULL,
  "lastSignalAt" TIMESTAMP(3) NOT NULL,
  "lastEventId" TEXT,
  "lastSpanId" TEXT,
  "lastBreachLevel" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS "ExecutionRiskState_executionId_category_key"
  ON "ExecutionRiskState"("executionId", "category");

CREATE INDEX IF NOT EXISTS "ExecutionRiskState_rootExecutionId_lastSignalAt_idx"
  ON "ExecutionRiskState"("rootExecutionId", "lastSignalAt" DESC);

CREATE INDEX IF NOT EXISTS "ExecutionRiskState_agentInstanceId_lastSignalAt_idx"
  ON "ExecutionRiskState"("agentInstanceId", "lastSignalAt" DESC);

CREATE INDEX IF NOT EXISTS "ExecutionRiskState_status_lastSignalAt_idx"
  ON "ExecutionRiskState"("status", "lastSignalAt" DESC);

CREATE INDEX IF NOT EXISTS "ExecutionRiskState_category_lastSignalAt_idx"
  ON "ExecutionRiskState"("category", "lastSignalAt" DESC);
