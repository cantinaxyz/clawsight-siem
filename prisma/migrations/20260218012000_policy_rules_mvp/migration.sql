-- CreateTable
CREATE TABLE "PolicyRule" (
    "id" SERIAL NOT NULL,
    "name" TEXT NOT NULL,
    "scope" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "priority" INTEGER NOT NULL DEFAULT 100,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "toolName" TEXT,
    "commandContains" TEXT,
    "channelId" TEXT,
    "toContains" TEXT,
    "contentContains" TEXT,
    "modifyContent" TEXT,
    "modifyParams" JSONB,
    "reason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "PolicyRule_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "PolicyRule_scope_enabled_priority_id_idx" ON "PolicyRule"("scope", "enabled", "priority", "id");

-- CreateIndex
CREATE INDEX "PolicyRule_toolName_idx" ON "PolicyRule"("toolName");

-- CreateIndex
CREATE INDEX "PolicyRule_channelId_idx" ON "PolicyRule"("channelId");
