ALTER TABLE "TelemetryEvent"
  ADD COLUMN IF NOT EXISTS "agentName" TEXT;

CREATE INDEX IF NOT EXISTS "TelemetryEvent_agentName_ts_idx"
  ON "TelemetryEvent" ("agentName", "ts" DESC);

ALTER TABLE "ManagedAgent"
  ADD COLUMN IF NOT EXISTS "openclawSessionId" TEXT,
  ADD COLUMN IF NOT EXISTS "reportedName" TEXT,
  ADD COLUMN IF NOT EXISTS "runtimeMeta" JSONB,
  ADD COLUMN IF NOT EXISTS "lastBootstrapAt" TIMESTAMP(3);

CREATE INDEX IF NOT EXISTS "ManagedAgent_openclawSessionId_lastSeenAt_idx"
  ON "ManagedAgent" ("openclawSessionId", "lastSeenAt" DESC);
