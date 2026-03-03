-- Alert lifecycle + investigation context
ALTER TABLE "ThreatAlert"
  ADD COLUMN "alertType" TEXT,
  ADD COLUMN "triggerType" TEXT,
  ADD COLUMN "executionId" TEXT,
  ADD COLUMN "topTool" TEXT,
  ADD COLUMN "topDomain" TEXT,
  ADD COLUMN "driftScore" INTEGER,
  ADD COLUMN "owner" TEXT,
  ADD COLUMN "ackAt" TIMESTAMP(3),
  ADD COLUMN "resolvedAt" TIMESTAMP(3),
  ADD COLUMN "resolutionNote" TEXT,
  ADD COLUMN "classification" TEXT;

CREATE INDEX "ThreatAlert_alertType_ts_idx"
  ON "ThreatAlert"("alertType", "ts" DESC);
CREATE INDEX "ThreatAlert_triggerType_ts_idx"
  ON "ThreatAlert"("triggerType", "ts" DESC);
CREATE INDEX "ThreatAlert_executionId_ts_idx"
  ON "ThreatAlert"("executionId", "ts" DESC);
CREATE INDEX "ThreatAlert_agentInstanceId_status_ts_idx"
  ON "ThreatAlert"("agentInstanceId", "status", "ts" DESC);
