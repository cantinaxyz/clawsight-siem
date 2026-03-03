/**
 * @fileoverview ClawSight SIEM module: platform/src/app/api/security/alerts/route.ts.
 */
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

type Query = {
  severity?: string;
  status?: string;
  alertModel?: string;
  includeLegacy?: boolean;
  alertType?: string;
  triggerType?: string;
  classification?: string;
  owner?: string;
  eventOutcome?: string;
  ruleId?: string;
  requestId?: string;
  executionId?: string;
  projectId?: string;
  ruleCategory?: string;
  eventCategory?: string;
  minRisk?: number;
  sinceHours?: number;
  limit?: number;
};

function parsePositiveInt(value: string | null, fallback: number): number {
  if (!value) return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) return fallback;
  return Math.min(parsed, 5000);
}

function parseNonNegativeInt(value: string | null, fallback: number): number {
  if (!value) return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) return fallback;
  return Math.min(parsed, 100);
}

/**
 * Lists alerts with filterable security dimensions for dashboard and integrations.
 */
export async function GET(request: NextRequest) {
  try {
    const url = new URL(request.url);
    const q = url.searchParams;
    const filters: Query = {
      severity: q.get("severity")?.trim(),
      status: q.get("status")?.trim(),
      alertModel: q.get("alertModel")?.trim(),
      includeLegacy: q.get("includeLegacy") === "1",
      alertType: q.get("alertType")?.trim(),
      triggerType: q.get("triggerType")?.trim(),
      classification: q.get("classification")?.trim(),
      owner: q.get("owner")?.trim(),
      eventOutcome: q.get("eventOutcome")?.trim() || q.get("outcome")?.trim(),
      ruleId: q.get("ruleId")?.trim(),
      requestId: q.get("requestId")?.trim(),
      executionId: q.get("executionId")?.trim(),
      projectId: q.get("projectId")?.trim(),
      ruleCategory: q.get("ruleCategory")?.trim(),
      eventCategory: q.get("eventCategory")?.trim(),
      minRisk: parseNonNegativeInt(q.get("minRisk"), 0),
      sinceHours: parseNonNegativeInt(q.get("sinceHours"), 24),
      limit: parsePositiveInt(q.get("limit"), 200),
    };

    const where: Record<string, unknown> = {};
    if (filters.severity) {
      where.ruleSeverity = filters.severity;
    }
    if (filters.status) {
      where.status = filters.status;
    }
    if (!filters.includeLegacy) {
      where.alertModel = filters.alertModel || "execution_v2";
    } else if (filters.alertModel) {
      where.alertModel = filters.alertModel;
    }
    if (filters.alertType) {
      where.alertType = filters.alertType;
    }
    if (filters.triggerType) {
      where.triggerType = filters.triggerType;
    }
    if (filters.classification) {
      where.classification = filters.classification;
    }
    if (filters.owner) {
      where.owner = filters.owner;
    }
    if (filters.eventOutcome) {
      where.eventOutcome = filters.eventOutcome;
    }
    if (filters.ruleId) {
      where.ruleId = filters.ruleId;
    }
    if (filters.requestId) {
      where.requestId = filters.requestId;
    }
    if (filters.executionId) {
      where.executionId = filters.executionId;
    }
    if (filters.projectId) {
      where.projectId = filters.projectId;
    }
    if (filters.ruleCategory) {
      where.ruleCategory = filters.ruleCategory;
    }
    if (filters.eventCategory) {
      where.eventCategory = filters.eventCategory;
    }
    if (filters.minRisk && filters.minRisk > 0) {
      where.riskScore = { gte: filters.minRisk };
    }
    if (filters.sinceHours) {
      const since = new Date(Date.now() - filters.sinceHours * 60 * 60 * 1000);
      where.ts = { gte: since };
    }

    const [alerts, total] = await Promise.all([
      prisma.threatAlert.findMany({
        where,
        orderBy: [{ ts: "desc" }],
        take: filters.limit,
      }),
      prisma.threatAlert.count({ where }),
    ]);

    return NextResponse.json({
      ok: true,
      total,
      data: alerts.map((alert) => ({
        ...alert,
        ts: alert.ts.getTime(),
      })),
    });
  } catch (err) {
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}
