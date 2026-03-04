-- Normalize legacy rows into explicit default project scope.
UPDATE "ExecutionRiskState"
SET "projectId" = 'default'
WHERE "projectId" IS NULL OR BTRIM("projectId") = '';

-- Keep only the newest row per scoped identity if historical duplicates exist.
WITH ranked AS (
  SELECT
    "id",
    ROW_NUMBER() OVER (
      PARTITION BY "projectId", "executionId", "category"
      ORDER BY "updatedAt" DESC, "id" DESC
    ) AS rn
  FROM "ExecutionRiskState"
)
DELETE FROM "ExecutionRiskState" state
USING ranked
WHERE state."id" = ranked."id" AND ranked.rn > 1;

ALTER TABLE "ExecutionRiskState"
  ALTER COLUMN "projectId" SET DEFAULT 'default',
  ALTER COLUMN "projectId" SET NOT NULL;

DROP INDEX IF EXISTS "ExecutionRiskState_executionId_category_key";

CREATE UNIQUE INDEX IF NOT EXISTS "ExecutionRiskState_projectId_executionId_category_key"
  ON "ExecutionRiskState"("projectId", "executionId", "category");

CREATE INDEX IF NOT EXISTS "ExecutionRiskState_projectId_lastSignalAt_idx"
  ON "ExecutionRiskState"("projectId", "lastSignalAt" DESC);
