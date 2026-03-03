/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/alerts/migrate-to-execution-v2.ts.
 */
import { Prisma } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import {
  buildExecutionRiskAlerts,
  mapExecutionAlertCategory,
  type ExecutionRiskSignal,
} from "@/lib/alerts/execution-risk";

type MigrationOptions = {
  dryRun?: boolean;
};

export type MigrationResult = {
  legacyAlerts: number;
  executionAlertsCreated: number;
  executionRiskStates: number;
  migratedAt: string;
  dryRun: boolean;
};

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function asString(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function asNumber(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return Math.round(value);
  if (typeof value === "string") {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return Math.round(parsed);
  }
  return null;
}

function normalizeExecutionId(alert: {
  executionId?: string | null;
  requestId?: string | null;
  id: number;
  details?: Prisma.JsonValue | null;
}): string {
  const details = asRecord(alert.details);
  return (
    asString(alert.executionId) ||
    asString(details?.executionId) ||
    asString(details?.traceId) ||
    asString(details?.rootExecutionId) ||
    asString(alert.requestId) ||
    `legacy:${alert.id}`
  );
}

function normalizeRootExecutionId(alert: {
  rootExecutionId?: string | null;
  details?: Prisma.JsonValue | null;
  executionId?: string | null;
  requestId?: string | null;
  id: number;
}): string {
  const details = asRecord(alert.details);
  return (
    asString(alert.rootExecutionId) ||
    asString(details?.rootExecutionId) ||
    normalizeExecutionId(alert)
  );
}

function toSignal(alert: {
  id: number;
  ts: Date;
  eventId?: string | null;
  executionId?: string | null;
  rootExecutionId?: string | null;
  requestId?: string | null;
  projectId?: string | null;
  agentInstanceId?: string | null;
  openclawAgentId?: string | null;
  openclawSessionKey?: string | null;
  triggerType?: string | null;
  alertType?: string | null;
  ruleId: string;
  ruleName: string;
  ruleCategory: string;
  ruleDescription?: string | null;
  ruleSeverity: string;
  eventCategory?: string | null;
  eventAction?: string | null;
  eventOutcome?: string | null;
  riskScore?: number | null;
  driftScore?: number | null;
  topTool?: string | null;
  topDomain?: string | null;
  details?: Prisma.JsonValue | null;
}): ExecutionRiskSignal {
  const details = asRecord(alert.details);
  const executionId = normalizeExecutionId(alert);
  const rootExecutionId = normalizeRootExecutionId(alert);
  const spanId = asString(details?.spanId);
  const outcomeReason = asString(details?.outcomeReason) || asString(details?.reason);
  const driftScore = alert.driftScore ?? asNumber(details?.driftScore) ?? asNumber(details?.maxDriftScore);
  const eventOutcome = alert.eventOutcome || asString(details?.outcome) || "warn";
  const category = mapExecutionAlertCategory({
    alertType: alert.alertType,
    eventCategory: alert.eventCategory,
    eventOutcome,
    ruleCategory: alert.ruleCategory,
    ruleId: alert.ruleId,
  });

  return {
    ts: alert.ts,
    eventId: asString(alert.eventId) || `legacy-alert:${alert.id}`,
    spanId,
    executionId,
    rootExecutionId,
    projectId: alert.projectId ?? null,
    agentInstanceId: alert.agentInstanceId ?? null,
    openclawAgentId: alert.openclawAgentId ?? null,
    openclawSessionKey: alert.openclawSessionKey ?? null,
    requestId: alert.requestId ?? null,
    triggerType: alert.triggerType ?? null,
    category,
    alertType: alert.alertType || "execution_anomaly",
    ruleId: alert.ruleId,
    ruleName: alert.ruleName,
    ruleCategory: alert.ruleCategory,
    ruleDescription: alert.ruleDescription ?? null,
    ruleSeverity: alert.ruleSeverity,
    eventCategory: alert.eventCategory ?? null,
    eventAction: alert.eventAction ?? null,
    eventOutcome,
    outcomeReason,
    riskScore: alert.riskScore ?? null,
    driftScore: driftScore ?? null,
    toolName: alert.topTool ?? null,
    domain: alert.topDomain ?? null,
  };
}

export async function migrateLegacyAlertsToExecutionV2(options: MigrationOptions = {}): Promise<MigrationResult> {
  const dryRun = Boolean(options.dryRun);

  const legacyAlerts = await prisma.threatAlert.findMany({
    where: {
      alertModel: { not: "execution_v2" },
    },
    orderBy: [{ ts: "asc" }, { id: "asc" }],
  });

  if (!legacyAlerts.length) {
    return {
      legacyAlerts: 0,
      executionAlertsCreated: 0,
      executionRiskStates: 0,
      migratedAt: new Date().toISOString(),
      dryRun,
    };
  }

  const signals = legacyAlerts.map((alert) => toSignal(alert));

  if (dryRun) {
    return {
      legacyAlerts: legacyAlerts.length,
      executionAlertsCreated: 0,
      executionRiskStates: 0,
      migratedAt: new Date().toISOString(),
      dryRun,
    };
  }

  const result = await prisma.$transaction(async (tx) => {
    await tx.executionRiskState.deleteMany({});
    await tx.threatAlert.deleteMany({ where: { alertModel: "execution_v2" } });

    await tx.$executeRaw`
      UPDATE "ThreatAlert"
      SET
        "alertModel" = 'legacy_event_v1',
        "status" = CASE
          WHEN LOWER(COALESCE("status", '')) IN ('resolved', 'false_positive') THEN "status"
          ELSE 'resolved'
        END,
        "ackAt" = COALESCE("ackAt", NOW()),
        "resolvedAt" = COALESCE("resolvedAt", NOW()),
        "classification" = COALESCE("classification", 'benign_anomaly'),
        "updatedAt" = NOW()
      WHERE "alertModel" <> 'execution_v2' OR "alertModel" IS NULL
    `;

    const executionAlerts = await buildExecutionRiskAlerts(tx, signals);
    const inserted =
      executionAlerts.length > 0
        ? await tx.threatAlert.createMany({ data: executionAlerts, skipDuplicates: true })
        : { count: 0 };

    const states = await tx.executionRiskState.count();
    return {
      executionAlertsCreated: inserted.count,
      executionRiskStates: states,
    };
  });

  return {
    legacyAlerts: legacyAlerts.length,
    executionAlertsCreated: result.executionAlertsCreated,
    executionRiskStates: result.executionRiskStates,
    migratedAt: new Date().toISOString(),
    dryRun,
  };
}
