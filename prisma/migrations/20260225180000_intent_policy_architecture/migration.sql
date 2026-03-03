-- Intent-based policy architecture

CREATE TABLE "IntentPolicyConfig" (
  "id" SERIAL NOT NULL,
  "configKey" TEXT NOT NULL,
  "scopeLevel" TEXT NOT NULL DEFAULT 'global',
  "managedAgentKey" TEXT,
  "mode" TEXT NOT NULL DEFAULT 'audit',
  "llmEnabled" BOOLEAN NOT NULL DEFAULT true,
  "baselineModel" TEXT NOT NULL DEFAULT 'gpt-4.1-mini',
  "alignmentModel" TEXT NOT NULL DEFAULT 'gpt-4.1-mini',
  "outputModel" TEXT NOT NULL DEFAULT 'gpt-4.1-mini',
  "outputSanitization" BOOLEAN NOT NULL DEFAULT true,
  "driftWarnThreshold" INTEGER NOT NULL DEFAULT 35,
  "driftBlockThreshold" INTEGER NOT NULL DEFAULT 70,
  "ambiguousLowerBound" INTEGER NOT NULL DEFAULT 30,
  "ambiguousUpperBound" INTEGER NOT NULL DEFAULT 60,
  "failMode" TEXT NOT NULL DEFAULT 'fail_open',
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,

  CONSTRAINT "IntentPolicyConfig_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "IntentPolicyConfig_configKey_key" ON "IntentPolicyConfig"("configKey");
CREATE INDEX "IntentPolicyConfig_scopeLevel_managedAgentKey_updatedAt_idx"
  ON "IntentPolicyConfig"("scopeLevel", "managedAgentKey", "updatedAt" DESC);

CREATE TABLE "ExecutionIntent" (
  "id" SERIAL NOT NULL,
  "executionKey" TEXT NOT NULL,
  "rootExecutionId" TEXT NOT NULL,
  "agentInstanceId" TEXT,
  "agentName" TEXT,
  "managedAgentKey" TEXT,
  "projectId" TEXT,
  "sessionKey" TEXT,
  "runId" TEXT,
  "sourceType" TEXT,
  "userPrompt" TEXT,
  "taskBoundary" TEXT,
  "expectedScopes" JSONB,
  "expectedDomains" JSONB,
  "sensitiveContext" BOOLEAN NOT NULL DEFAULT false,
  "confidence" INTEGER,
  "extractionMethod" TEXT NOT NULL DEFAULT 'heuristic',
  "status" TEXT NOT NULL DEFAULT 'active',
  "driftScore" INTEGER NOT NULL DEFAULT 0,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,

  CONSTRAINT "ExecutionIntent_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "ExecutionIntent_executionKey_key" ON "ExecutionIntent"("executionKey");
CREATE INDEX "ExecutionIntent_rootExecutionId_createdAt_idx"
  ON "ExecutionIntent"("rootExecutionId", "createdAt" DESC);
CREATE INDEX "ExecutionIntent_agentInstanceId_createdAt_idx"
  ON "ExecutionIntent"("agentInstanceId", "createdAt" DESC);
CREATE INDEX "ExecutionIntent_managedAgentKey_createdAt_idx"
  ON "ExecutionIntent"("managedAgentKey", "createdAt" DESC);
CREATE INDEX "ExecutionIntent_status_createdAt_idx"
  ON "ExecutionIntent"("status", "createdAt" DESC);

CREATE TABLE "IntentDecision" (
  "id" SERIAL NOT NULL,
  "executionKey" TEXT,
  "rootExecutionId" TEXT NOT NULL,
  "agentInstanceId" TEXT,
  "requestId" TEXT,
  "traceId" TEXT,
  "spanId" TEXT,
  "phase" TEXT NOT NULL,
  "toolName" TEXT,
  "targetDomain" TEXT,
  "action" TEXT NOT NULL,
  "scoreDelta" INTEGER NOT NULL DEFAULT 0,
  "driftScore" INTEGER NOT NULL DEFAULT 0,
  "confidence" INTEGER,
  "reason" TEXT,
  "signals" JSONB,
  "details" JSONB,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,

  CONSTRAINT "IntentDecision_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "IntentDecision_rootExecutionId_createdAt_idx"
  ON "IntentDecision"("rootExecutionId", "createdAt" DESC);
CREATE INDEX "IntentDecision_executionKey_createdAt_idx"
  ON "IntentDecision"("executionKey", "createdAt" DESC);
CREATE INDEX "IntentDecision_agentInstanceId_createdAt_idx"
  ON "IntentDecision"("agentInstanceId", "createdAt" DESC);
CREATE INDEX "IntentDecision_phase_createdAt_idx"
  ON "IntentDecision"("phase", "createdAt" DESC);
CREATE INDEX "IntentDecision_action_createdAt_idx"
  ON "IntentDecision"("action", "createdAt" DESC);
CREATE INDEX "IntentDecision_requestId_createdAt_idx"
  ON "IntentDecision"("requestId", "createdAt" DESC);

ALTER TABLE "IntentDecision"
  ADD CONSTRAINT "IntentDecision_executionKey_fkey"
  FOREIGN KEY ("executionKey")
  REFERENCES "ExecutionIntent"("executionKey")
  ON DELETE SET NULL
  ON UPDATE CASCADE;
