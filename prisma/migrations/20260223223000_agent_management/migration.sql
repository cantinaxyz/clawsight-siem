-- Agent management registry + agent-scoped policy support

ALTER TABLE "PolicyRule"
  ADD COLUMN "scopeLevel" TEXT NOT NULL DEFAULT 'global',
  ADD COLUMN "managedAgentKey" TEXT;

CREATE INDEX "PolicyRule_scopeLevel_managedAgentKey_enabled_priority_id_idx"
  ON "PolicyRule"("scopeLevel", "managedAgentKey", "enabled", "priority", "id");

CREATE TABLE "ManagedAgent" (
  "id" SERIAL NOT NULL,
  "agentKey" TEXT NOT NULL,
  "displayName" TEXT,
  "projectId" TEXT,
  "agentInstanceId" TEXT,
  "openclawAgentId" TEXT,
  "sourceType" TEXT NOT NULL DEFAULT 'discovered',
  "managed" BOOLEAN NOT NULL DEFAULT false,
  "policyProfile" TEXT NOT NULL DEFAULT 'inherit_global',
  "notes" TEXT,
  "firstSeenAt" TIMESTAMP(3) NOT NULL,
  "lastSeenAt" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "ManagedAgent_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "ManagedAgent_agentKey_key" ON "ManagedAgent"("agentKey");
CREATE INDEX "ManagedAgent_projectId_lastSeenAt_idx" ON "ManagedAgent"("projectId", "lastSeenAt" DESC);
CREATE INDEX "ManagedAgent_managed_lastSeenAt_idx" ON "ManagedAgent"("managed", "lastSeenAt" DESC);
