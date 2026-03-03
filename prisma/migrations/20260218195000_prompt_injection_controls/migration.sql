-- Prompt-injection controls: config + rules + decision logs

CREATE TABLE "PromptInjectionConfig" (
    "id" INTEGER NOT NULL,
    "llmEnabled" BOOLEAN NOT NULL DEFAULT true,
    "model" TEXT NOT NULL DEFAULT 'gpt-4.1-mini',
    "timeoutMs" INTEGER NOT NULL DEFAULT 4500,
    "failMode" TEXT NOT NULL DEFAULT 'fail_open',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PromptInjectionConfig_pkey" PRIMARY KEY ("id")
);

INSERT INTO "PromptInjectionConfig" ("id", "llmEnabled", "model", "timeoutMs", "failMode", "createdAt", "updatedAt")
VALUES (1, true, 'gpt-4.1-mini', 4500, 'fail_open', NOW(), NOW())
ON CONFLICT ("id") DO NOTHING;

CREATE TABLE "PromptInjectionRule" (
    "id" SERIAL NOT NULL,
    "name" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "priority" INTEGER NOT NULL DEFAULT 100,
    "surface" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "patternType" TEXT NOT NULL,
    "patternValue" TEXT,
    "channelId" TEXT,
    "senderContains" TEXT,
    "toolName" TEXT,
    "llmCheck" BOOLEAN NOT NULL DEFAULT false,
    "reason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PromptInjectionRule_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "PromptInjectionRule_enabled_surface_priority_id_idx"
  ON "PromptInjectionRule"("enabled", "surface", "priority", "id");
CREATE INDEX "PromptInjectionRule_patternType_idx" ON "PromptInjectionRule"("patternType");
CREATE INDEX "PromptInjectionRule_channelId_idx" ON "PromptInjectionRule"("channelId");
CREATE INDEX "PromptInjectionRule_toolName_idx" ON "PromptInjectionRule"("toolName");

CREATE TABLE "PromptInjectionDecision" (
    "id" SERIAL NOT NULL,
    "ruleId" INTEGER,
    "requestId" TEXT,
    "eventId" TEXT,
    "sessionKey" TEXT,
    "toolName" TEXT,
    "channelId" TEXT,
    "sender" TEXT,
    "surface" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "enforcement" TEXT NOT NULL,
    "reason" TEXT,
    "signals" JSONB,
    "inputHash" TEXT,
    "modelVerdict" TEXT,
    "modelConfidence" INTEGER,
    "modelReason" TEXT,
    "latencyMs" INTEGER,
    "modelError" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PromptInjectionDecision_pkey" PRIMARY KEY ("id")
);

ALTER TABLE "PromptInjectionDecision"
  ADD CONSTRAINT "PromptInjectionDecision_ruleId_fkey"
  FOREIGN KEY ("ruleId") REFERENCES "PromptInjectionRule"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;

CREATE INDEX "PromptInjectionDecision_surface_createdAt_idx"
  ON "PromptInjectionDecision"("surface", "createdAt" DESC);
CREATE INDEX "PromptInjectionDecision_action_createdAt_idx"
  ON "PromptInjectionDecision"("action", "createdAt" DESC);
CREATE INDEX "PromptInjectionDecision_requestId_createdAt_idx"
  ON "PromptInjectionDecision"("requestId", "createdAt" DESC);
CREATE INDEX "PromptInjectionDecision_ruleId_createdAt_idx"
  ON "PromptInjectionDecision"("ruleId", "createdAt" DESC);
