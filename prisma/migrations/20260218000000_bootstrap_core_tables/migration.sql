-- Bootstrap core SIEM tables so migration chain replays cleanly from empty shadow DB.
-- Uses IF NOT EXISTS to remain safe on already-provisioned dev databases.

CREATE TABLE IF NOT EXISTS "TelemetryEvent" (
  "id" SERIAL NOT NULL,
  "eventId" TEXT NOT NULL,
  "ts" TIMESTAMP(3) NOT NULL,
  "severity" TEXT NOT NULL DEFAULT 'info',
  "category" TEXT NOT NULL,
  "action" TEXT NOT NULL,
  "projectId" TEXT,
  "agentInstanceId" TEXT,
  "requestId" TEXT,
  "correlationId" TEXT,
  "result" TEXT,
  "durationMs" INTEGER,
  "sourceIp" TEXT,
  "sourceHost" TEXT,
  "sourcePort" INTEGER,
  "iocType" TEXT,
  "iocValue" TEXT,
  "riskScore" INTEGER,
  "openclawAgentId" TEXT,
  "openclawSessionKey" TEXT,
  "openclawSessionId" TEXT,
  "openclawRunId" TEXT,
  "openclawToolName" TEXT,
  "openclawToolCallId" TEXT,
  "openclawGatewayPort" INTEGER,
  "payload" JSONB,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "TelemetryEvent_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "TelemetryEvent_eventId_key" ON "TelemetryEvent"("eventId");
CREATE INDEX IF NOT EXISTS "TelemetryEvent_category_ts_idx" ON "TelemetryEvent"("category", "ts" DESC);
CREATE INDEX IF NOT EXISTS "TelemetryEvent_projectId_ts_idx" ON "TelemetryEvent"("projectId", "ts" DESC);
CREATE INDEX IF NOT EXISTS "TelemetryEvent_agentInstanceId_ts_idx" ON "TelemetryEvent"("agentInstanceId", "ts" DESC);
CREATE INDEX IF NOT EXISTS "TelemetryEvent_requestId_idx" ON "TelemetryEvent"("requestId");

CREATE TABLE IF NOT EXISTS "ThreatAlert" (
  "id" SERIAL NOT NULL,
  "alertKey" TEXT NOT NULL,
  "ts" TIMESTAMP(3) NOT NULL,
  "ruleId" TEXT NOT NULL,
  "ruleName" TEXT NOT NULL,
  "ruleSeverity" TEXT NOT NULL,
  "ruleCategory" TEXT NOT NULL,
  "ruleDescription" TEXT,
  "eventCategory" TEXT,
  "eventAction" TEXT,
  "eventId" TEXT,
  "requestId" TEXT,
  "projectId" TEXT,
  "agentInstanceId" TEXT,
  "openclawAgentId" TEXT,
  "openclawSessionKey" TEXT,
  "sourceIp" TEXT,
  "riskScore" INTEGER,
  "details" JSONB,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "ThreatAlert_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "ThreatAlert_alertKey_key" ON "ThreatAlert"("alertKey");
CREATE INDEX IF NOT EXISTS "ThreatAlert_ruleId_ts_idx" ON "ThreatAlert"("ruleId", "ts" DESC);
CREATE INDEX IF NOT EXISTS "ThreatAlert_ruleSeverity_ts_idx" ON "ThreatAlert"("ruleSeverity", "ts" DESC);
CREATE INDEX IF NOT EXISTS "ThreatAlert_requestId_ts_idx" ON "ThreatAlert"("requestId", "ts" DESC);
