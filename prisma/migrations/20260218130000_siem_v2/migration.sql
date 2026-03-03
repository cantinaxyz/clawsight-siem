-- SIEM v2 normalized telemetry schema evolution

ALTER TABLE "TelemetryEvent"
  ADD COLUMN "traceId" TEXT,
  ADD COLUMN "spanId" TEXT,
  ADD COLUMN "outcome" TEXT,
  ADD COLUMN "outcomeReason" TEXT,
  ADD COLUMN "policyRuleId" TEXT,
  ADD COLUMN "policyDecisionId" TEXT,
  ADD COLUMN "latencyMs" INTEGER,
  ADD COLUMN "errorClass" TEXT,
  ADD COLUMN "errorCode" TEXT,
  ADD COLUMN "toolExitCode" INTEGER,
  ADD COLUMN "schemaVersion" INTEGER NOT NULL DEFAULT 2,
  ADD COLUMN "payloadRedacted" JSONB,
  ADD COLUMN "payloadHash" TEXT,
  ADD COLUMN "payloadBytes" INTEGER;

CREATE INDEX "TelemetryEvent_outcome_ts_idx" ON "TelemetryEvent"("outcome", "ts" DESC);
CREATE INDEX "TelemetryEvent_policyRuleId_ts_idx" ON "TelemetryEvent"("policyRuleId", "ts" DESC);
CREATE INDEX "TelemetryEvent_openclawToolName_ts_idx" ON "TelemetryEvent"("openclawToolName", "ts" DESC);

ALTER TABLE "ThreatAlert"
  ADD COLUMN "status" TEXT NOT NULL DEFAULT 'open',
  ADD COLUMN "eventOutcome" TEXT,
  ADD COLUMN "dedupeKey" TEXT;

CREATE UNIQUE INDEX "ThreatAlert_dedupeKey_key" ON "ThreatAlert"("dedupeKey");
CREATE INDEX "ThreatAlert_status_ts_idx" ON "ThreatAlert"("status", "ts" DESC);
CREATE INDEX "ThreatAlert_eventOutcome_ts_idx" ON "ThreatAlert"("eventOutcome", "ts" DESC);

CREATE TABLE "TelemetryObservable" (
  "id" SERIAL PRIMARY KEY,
  "eventId" INTEGER NOT NULL,
  "eventTs" TIMESTAMP(3) NOT NULL,
  "kind" TEXT NOT NULL,
  "value" TEXT NOT NULL,
  "valueHash" TEXT NOT NULL,
  "confidence" INTEGER,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE "TelemetryObservable"
  ADD CONSTRAINT "TelemetryObservable_eventId_fkey"
  FOREIGN KEY ("eventId") REFERENCES "TelemetryEvent"("id") ON DELETE CASCADE ON UPDATE CASCADE;

CREATE UNIQUE INDEX "TelemetryObservable_eventId_kind_valueHash_key"
  ON "TelemetryObservable"("eventId", "kind", "valueHash");
CREATE INDEX "TelemetryObservable_eventId_idx" ON "TelemetryObservable"("eventId");
CREATE INDEX "TelemetryObservable_kind_valueHash_idx" ON "TelemetryObservable"("kind", "valueHash");
CREATE INDEX "TelemetryObservable_kind_eventTs_idx" ON "TelemetryObservable"("kind", "eventTs" DESC);
