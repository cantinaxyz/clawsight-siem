/**
 * @fileoverview ClawSight SIEM module: platform/src/app/alerts/page.tsx.
 */
import Link from "next/link";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { Prisma } from "@prisma/client";
import { AlertTriangle, CheckCheck, ChevronRight, ExternalLink, Search, ShieldAlert, X } from "lucide-react";
import AppShell from "@/components/app-shell";
import { discoverManagedAgents } from "@/lib/agents/discovery";
import { parseManagedAgentKey } from "@/lib/agents/identity";
import { listManagedAgents } from "@/lib/agents/repository";
import {
  normalizeAlertClassification,
  normalizeAlertStatus,
  requiresResolutionNote,
  type AlertClassification,
  type AlertStatus,
} from "@/lib/alerts/lifecycle";
import { prisma } from "@/lib/prisma";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

type SearchParams = {
  q?: string;
  severity?: string;
  status?: string;
  alertModel?: string;
  includeLegacy?: string;
  alertType?: string;
  triggerType?: string;
  outcome?: string;
  ruleId?: string;
  requestId?: string;
  agentKey?: string;
  projectId?: string;
  minRisk?: string;
  limit?: string;
  select?: string;
  alertId?: string;
  focus?: string;
};

type AlertRecord = Awaited<ReturnType<typeof prisma.threatAlert.findMany>>[number];

type IntentBaselineRow = {
  executionKey: string;
  rootExecutionId: string;
  taskBoundary: string | null;
  expectedScopes: unknown;
  expectedDomains: unknown;
  driftScore: number;
  extractionMethod: string | null;
  status: string | null;
  updatedAt: Date;
};

type IntentDecisionRow = {
  id: number;
  phase: string;
  action: string;
  scoreDelta: number;
  driftScore: number;
  confidence: number | null;
  reason: string | null;
  toolName: string | null;
  targetDomain: string | null;
  createdAt: Date;
};

type ToolAggRow = {
  toolName: string;
  calls: number;
  errors: number;
};

type DomainAggRow = {
  domain: string;
  calls: number;
};

type CorrelatedEventRow = {
  id: number;
  ts: Date;
  category: string;
  action: string;
  severity: string;
  outcome: string | null;
  outcomeReason: string | null;
  errorClass: string | null;
  errorCode: string | null;
  durationMs: number | null;
  openclawToolName: string | null;
  openclawToolCallId: string | null;
  payload: unknown;
  payloadRedacted: unknown;
};

type CorrelatedTimelineItem = {
  key: string;
  ts: Date;
  event: string;
  detail: string;
  drift?: number | null;
  status?: string;
};

type GroupedAlerts = {
  rootKey: string;
  alerts: AlertRecord[];
  latestTs: Date;
  openCount: number;
  maxSeverity: string;
};

function parseId(value: string | undefined): number | null {
  if (!value) return null;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) return null;
  return parsed;
}

function formatDate(ts: Date): string {
  return new Date(ts).toLocaleString("en-US", {
    month: "2-digit",
    day: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

function shortId(value: string | null | undefined, size = 14): string {
  if (!value) return "-";
  return value.length > size ? `${value.slice(0, size)}...` : value;
}

function compactGroupId(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return "unknown";
  const tail = trimmed.split(":").filter(Boolean).at(-1) || trimmed;
  const normalized = tail.replace(/[^a-zA-Z0-9]/g, "");
  if (normalized.length >= 8) return normalized.slice(0, 8);
  const fallback = trimmed.replace(/[^a-zA-Z0-9]/g, "");
  return (fallback || "unknown").slice(0, 8);
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function readDetail(details: unknown, key: string): string | null {
  const rec = asRecord(details);
  if (!rec) return null;
  const value = rec[key];
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function toStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => String(item || "").trim())
    .filter((item) => item.length > 0);
}

function toPreview(value: unknown, max = 180): string {
  if (!value) return "-";
  if (typeof value === "string") return value.length <= max ? value : `${value.slice(0, max)}...`;
  try {
    const raw = JSON.stringify(value);
    return raw.length <= max ? raw : `${raw.slice(0, max)}...`;
  } catch {
    return String(value).slice(0, max);
  }
}

function readRecordValue(value: unknown, key: string): string | null {
  const rec = asRecord(value);
  if (!rec) return null;
  const raw = rec[key];
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function pickToolPreview(row: CorrelatedEventRow): string | null {
  const payload = row.payloadRedacted ?? row.payload;
  const direct =
    readRecordValue(payload, "preview") ||
    readRecordValue(payload, "command") ||
    readRecordValue(payload, "url") ||
    readRecordValue(payload, "domain");
  if (direct) return direct;

  const params = asRecord(asRecord(payload)?.params);
  if (!params) return null;
  return (
    readRecordValue(params, "preview") ||
    readRecordValue(params, "command") ||
    readRecordValue(params, "url") ||
    readRecordValue(params, "domain") ||
    readRecordValue(params, "host")
  );
}

/**
 * Resolves managed-agent scoping for alert queries.
 */
function buildManagedAgentAlertWhere(agentKey?: string | null): Prisma.ThreatAlertWhereInput | null {
  const parsed = parseManagedAgentKey(agentKey);
  if (!parsed) return null;

  const projectWhere: Prisma.ThreatAlertWhereInput =
    parsed.projectId === "default"
      ? { OR: [{ projectId: null }, { projectId: "" }, { projectId: "default" }] }
      : { projectId: parsed.projectId };

  if (parsed.kind === "inst") return { AND: [projectWhere, { agentInstanceId: parsed.value }] };
  if (parsed.kind === "oc") return { AND: [projectWhere, { openclawAgentId: parsed.value }] };
  if (parsed.kind === "sid") return { AND: [projectWhere, { openclawSessionKey: parsed.value }] };
  return { AND: [projectWhere, { openclawSessionKey: parsed.value }] };
}

/**
 * Builds Prisma alert filters from URL search params used by the alerts workbench.
 */
function buildAlertWhere(params: SearchParams): Prisma.ThreatAlertWhereInput {
  const where: Prisma.ThreatAlertWhereInput = {};
  const whereRec = where as Record<string, unknown>;
  const includeLegacy = params.includeLegacy === "1";
  const alertModel = String(params.alertModel || "").trim();

  if (!includeLegacy) {
    whereRec.alertModel = alertModel || "execution_v2";
  } else if (alertModel) {
    whereRec.alertModel = alertModel;
  }

  if (params.severity) where.ruleSeverity = params.severity;
  if (params.status) where.status = params.status;
  if (params.outcome) where.eventOutcome = params.outcome;
  if (params.alertType) whereRec.alertType = params.alertType;
  if (params.triggerType) whereRec.triggerType = params.triggerType;
  if (params.ruleId) where.ruleId = params.ruleId;
  if (params.requestId) where.requestId = params.requestId;
  if (params.projectId) where.projectId = params.projectId;

  if (params.agentKey) {
    const agentWhere = buildManagedAgentAlertWhere(params.agentKey);
    if (agentWhere) where.AND = [...(Array.isArray(where.AND) ? where.AND : []), agentWhere];
  }

  if (params.minRisk) {
    const minRisk = Number(params.minRisk);
    if (!Number.isNaN(minRisk)) where.riskScore = { gte: minRisk };
  }

  const q = (params.q || "").trim();
  if (q) {
    where.OR = [
      { ruleId: { contains: q, mode: "insensitive" } },
      { ruleName: { contains: q, mode: "insensitive" } },
      { ruleDescription: { contains: q, mode: "insensitive" } },
      { eventCategory: { contains: q, mode: "insensitive" } },
      { eventAction: { contains: q, mode: "insensitive" } },
      { requestId: { contains: q, mode: "insensitive" } },
      { executionId: { contains: q, mode: "insensitive" } },
      { topTool: { contains: q, mode: "insensitive" } },
      { topDomain: { contains: q, mode: "insensitive" } },
      { openclawAgentId: { contains: q, mode: "insensitive" } },
      { agentInstanceId: { contains: q, mode: "insensitive" } },
    ];
  }

  return where;
}

/**
 * Parses and deduplicates numeric IDs from multi-select form payloads.
 */
function parseIdList(values: FormDataEntryValue[]): number[] {
  const ids = new Set<number>();
  for (const value of values) {
    if (typeof value !== "string") continue;
    const parsed = Number(value);
    if (!Number.isInteger(parsed) || parsed <= 0) continue;
    ids.add(parsed);
  }
  return [...ids];
}

function parseReturnTo(formData: FormData): string {
  const raw = formData.get("returnTo");
  if (typeof raw !== "string" || !raw.startsWith("/alerts")) return "/alerts";
  return raw;
}

function severityRank(value: string): number {
  switch (value) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
    default:
      return 0;
  }
}

function severityBadgeClass(value?: string | null): string {
  switch (value) {
    case "critical":
      return "border-destructive/40 bg-destructive/10 text-destructive";
    case "high":
      return "border-orange-500/30 bg-orange-500/10 text-orange-300";
    case "medium":
      return "border-yellow-500/30 bg-yellow-500/10 text-yellow-300";
    case "low":
      return "border-blue-500/30 bg-blue-500/10 text-blue-300";
    default:
      return "border-border bg-secondary text-secondary-foreground";
  }
}

function statusBadgeClass(value?: string | null): string {
  switch (normalizeAlertStatus(value)) {
    case "open":
      return "border-destructive/40 bg-destructive/10 text-destructive";
    case "acknowledged":
      return "border-blue-500/30 bg-blue-500/10 text-blue-300";
    case "resolved":
      return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
    case "false_positive":
      return "border-zinc-500/30 bg-zinc-500/10 text-zinc-300";
    default:
      return "border-border bg-secondary text-secondary-foreground";
  }
}

function outcomeBadgeClass(value?: string | null): string {
  switch (value) {
    case "block":
      return "border-yellow-500/30 bg-yellow-500/10 text-yellow-300";
    case "error":
      return "border-orange-500/30 bg-orange-500/10 text-orange-300";
    case "modify":
      return "border-blue-500/30 bg-blue-500/10 text-blue-300";
    case "allow":
      return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
    default:
      return "border-border bg-secondary text-secondary-foreground";
  }
}

function alertTypeBadgeClass(value?: string | null): string {
  switch (String(value || "").toLowerCase()) {
    case "policy_block":
      return "border-yellow-500/30 bg-yellow-500/10 text-yellow-300";
    case "intent_drift":
      return "border-fuchsia-500/30 bg-fuchsia-500/10 text-fuchsia-300";
    case "tool_output_injection":
      return "border-red-500/30 bg-red-500/10 text-red-300";
    case "execution_error":
      return "border-orange-500/30 bg-orange-500/10 text-orange-300";
    default:
      return "border-border bg-secondary text-secondary-foreground";
  }
}

function executionRootKey(alert: AlertRecord): string {
  return (
    readDetail(alert.details, "rootExecutionId") ||
    alert.executionId ||
    readDetail(alert.details, "executionId") ||
    readDetail(alert.details, "traceId") ||
    alert.requestId ||
    `alert:${alert.id}`
  );
}

function executionKey(alert: AlertRecord): string | null {
  return (
    alert.executionId ||
    readDetail(alert.details, "executionId") ||
    readDetail(alert.details, "traceId") ||
    readDetail(alert.details, "rootExecutionId") ||
    null
  );
}

function toStatusText(value?: string | null): string {
  const normalized = normalizeAlertStatus(value);
  if (!normalized) return "open";
  return normalized;
}

async function bulkAlertTransitionAction(formData: FormData) {
  "use server";

  const returnTo = parseReturnTo(formData);
  const nextStatusRaw = formData.get("nextStatus");
  const nextStatus = normalizeAlertStatus(nextStatusRaw);
  if (!nextStatus || !["open", "acknowledged", "resolved", "false_positive"].includes(nextStatus)) {
    redirect(returnTo);
  }

  const ids = parseIdList(formData.getAll("ids"));
  if (ids.length === 0) {
    redirect(returnTo);
  }

  const now = new Date();
  const shouldOpen = nextStatus === "open";
  const shouldAck = nextStatus === "acknowledged";
  const isTerminal = nextStatus === "resolved" || nextStatus === "false_positive";

  await prisma.$executeRaw`
    UPDATE "ThreatAlert"
    SET
      "status" = ${nextStatus},
      "ackAt" = CASE
        WHEN ${shouldAck} THEN COALESCE("ackAt", ${now})
        WHEN ${shouldOpen} THEN NULL
        ELSE "ackAt"
      END,
      "resolvedAt" = CASE
        WHEN ${isTerminal} THEN ${now}
        WHEN ${shouldOpen} THEN NULL
        ELSE "resolvedAt"
      END,
      "resolutionNote" = CASE WHEN ${shouldOpen} THEN NULL ELSE "resolutionNote" END,
      "updatedAt" = NOW()
    WHERE "id" IN (${Prisma.join(ids)})
  `;

  revalidatePath("/alerts");
  redirect(returnTo);
}

async function resolveAlertAction(formData: FormData) {
  "use server";

  const returnTo = parseReturnTo(formData);
  const idRaw = formData.get("id");
  const nextRaw = formData.get("nextStatus");
  const noteRaw = formData.get("resolutionNote");
  const classificationRaw = formData.get("classification");

  const id = typeof idRaw === "string" ? parseId(idRaw) : null;
  const nextStatus = normalizeAlertStatus(nextRaw);
  const note = typeof noteRaw === "string" ? noteRaw.trim() : "";
  const classification = normalizeAlertClassification(classificationRaw);

  if (!id || !nextStatus || !["resolved", "false_positive"].includes(nextStatus)) {
    redirect(returnTo);
  }

  if (requiresResolutionNote(nextStatus) && note.length < 8) {
    redirect(`${returnTo}${returnTo.includes("?") ? "&" : "?"}error=resolution-note-required`);
  }

  const existing = await prisma.threatAlert.findUnique({ where: { id } });
  if (!existing) {
    redirect(returnTo);
  }

  const meta = existing as typeof existing & { classification?: string | null };
  const now = new Date();

  await prisma.$executeRaw`
    UPDATE "ThreatAlert"
    SET
      "status" = ${nextStatus},
      "ackAt" = COALESCE("ackAt", ${now}),
      "resolvedAt" = ${now},
      "resolutionNote" = ${note},
      "classification" = COALESCE(${classification ?? null}, ${meta.classification ?? null}),
      "updatedAt" = NOW()
    WHERE "id" = ${id}
  `;

  revalidatePath("/alerts");
  redirect(returnTo);
}

export default async function AlertsPage({ searchParams }: { searchParams: Promise<SearchParams> }) {
  const params = await searchParams;
  await discoverManagedAgents(200);
  const managedAgents = await listManagedAgents({ limit: 300 });

  const where = buildAlertWhere(params);
  const safeLimit = Math.min(Math.max(Number(params.limit) || 200, 20), 500);
  const selectionMode = params.select === "1";
  const focusMode = params.focus === "1";

  const [alerts, totalAlerts] = await Promise.all([
    prisma.threatAlert.findMany({ where, orderBy: { ts: "desc" }, take: safeLimit }),
    prisma.threatAlert.count({ where }),
  ]);

  const selectedId = parseId(params.alertId);
  const selectedAlert = alerts.find((item) => item.id === selectedId) || alerts[0] || null;

  const managedNames = new Map<string, string>();
  for (const agent of managedAgents) {
    const label = agent.displayName || agent.reportedName || agent.agentInstanceId || agent.agentKey;
    if (agent.agentInstanceId) managedNames.set(agent.agentInstanceId, label);
  }

  const groupsMap = new Map<string, GroupedAlerts>();
  for (const alert of alerts) {
    const key = executionRootKey(alert);
    const normalized = normalizeAlertStatus(alert.status);
    const group = groupsMap.get(key);
    if (!group) {
      groupsMap.set(key, {
        rootKey: key,
        alerts: [alert],
        latestTs: alert.ts,
        openCount: normalized === "open" ? 1 : 0,
        maxSeverity: alert.ruleSeverity,
      });
      continue;
    }
    group.alerts.push(alert);
    if (alert.ts > group.latestTs) group.latestTs = alert.ts;
    if (normalized === "open") group.openCount += 1;
    if (severityRank(alert.ruleSeverity) > severityRank(group.maxSeverity)) group.maxSeverity = alert.ruleSeverity;
  }

  const groups = [...groupsMap.values()]
    .map((group) => ({
      ...group,
      alerts: [...group.alerts].sort((a, b) => b.ts.getTime() - a.ts.getTime()),
    }))
    .sort((a, b) => b.latestTs.getTime() - a.latestTs.getTime());

  const selectedGroupKey = selectedAlert ? executionRootKey(selectedAlert) : null;

  const baseQuery = new URLSearchParams();
  if (params.q) baseQuery.set("q", params.q);
  if (params.severity) baseQuery.set("severity", params.severity);
  if (params.status) baseQuery.set("status", params.status);
  if (params.alertType) baseQuery.set("alertType", params.alertType);
  if (params.triggerType) baseQuery.set("triggerType", params.triggerType);
  if (params.outcome) baseQuery.set("outcome", params.outcome);
  if (params.ruleId) baseQuery.set("ruleId", params.ruleId);
  if (params.requestId) baseQuery.set("requestId", params.requestId);
  if (params.agentKey) baseQuery.set("agentKey", params.agentKey);
  if (params.projectId) baseQuery.set("projectId", params.projectId);
  if (params.minRisk) baseQuery.set("minRisk", params.minRisk);
  if (params.alertModel) baseQuery.set("alertModel", params.alertModel);
  if (params.includeLegacy === "1") baseQuery.set("includeLegacy", "1");
  baseQuery.set("limit", String(safeLimit));
  if (selectionMode) baseQuery.set("select", "1");
  if (focusMode) baseQuery.set("focus", "1");
  if (selectedAlert) baseQuery.set("alertId", String(selectedAlert.id));

  const hrefWith = (patch: Record<string, string | null | undefined>) => {
    const next = new URLSearchParams(baseQuery);
    for (const [key, value] of Object.entries(patch)) {
      if (!value) next.delete(key);
      else next.set(key, value);
    }
    const query = next.toString();
    return query ? `/alerts?${query}` : "/alerts";
  };

  const returnTo = hrefWith({});
  const doneHref = hrefWith({ select: null });
  const selectHref = hrefWith({ select: "1" });
  const focusHref = hrefWith({ focus: focusMode ? null : "1" });

  const hasActiveFilters = Boolean(
    params.q ||
      params.severity ||
      params.status ||
      params.alertType ||
      params.triggerType ||
      params.outcome ||
      params.ruleId ||
      params.requestId ||
      params.agentKey ||
      params.projectId ||
      params.minRisk,
  );
  const hasAdvancedFilters = Boolean(
    params.alertType ||
      params.triggerType ||
      params.outcome ||
      (params.limit && Number(params.limit) > 0 && Number(params.limit) !== 200),
  );

  const selectedExecutionId = selectedAlert ? executionKey(selectedAlert) : null;
  const selectedMeta = selectedAlert
    ? (selectedAlert as AlertRecord & {
        alertType?: string | null;
        triggerType?: string | null;
        executionId?: string | null;
        topTool?: string | null;
        topDomain?: string | null;
        driftScore?: number | null;
        classification?: string | null;
        resolutionNote?: string | null;
      })
    : null;

  const detailData = selectedAlert
    ? await (async () => {
        if (!selectedExecutionId) {
          return {
            trace: null,
            traceSpans: [] as Awaited<ReturnType<typeof prisma.traceSpan.findMany>>,
            baseline: null as IntentBaselineRow | null,
            decisions: [] as IntentDecisionRow[],
            tools: [] as ToolAggRow[],
            domains: [] as DomainAggRow[],
            correlatedEvents: [] as CorrelatedEventRow[],
          };
        }

        const [trace, traceSpans, baselineRows, decisions, tools, domains, correlatedEvents] =
          await Promise.all([
            prisma.trace.findUnique({ where: { traceId: selectedExecutionId } }),
            prisma.traceSpan.findMany({ where: { traceId: selectedExecutionId }, orderBy: { ts: "asc" }, take: 160 }),
            prisma.$queryRaw<Array<IntentBaselineRow>>(Prisma.sql`
              SELECT "executionKey", "rootExecutionId", "taskBoundary", "expectedScopes", "expectedDomains", "driftScore", "extractionMethod", "status", "updatedAt"
              FROM "ExecutionIntent"
              WHERE "executionKey" = ${selectedExecutionId} OR "rootExecutionId" = ${selectedExecutionId}
              ORDER BY "updatedAt" DESC
              LIMIT 1
            `),
            prisma.$queryRaw<Array<IntentDecisionRow>>(Prisma.sql`
              SELECT "id", "phase", "action", "scoreDelta", "driftScore", "confidence", "reason", "toolName", "targetDomain", "createdAt"
              FROM "IntentDecision"
              WHERE "executionKey" = ${selectedExecutionId} OR "rootExecutionId" = ${selectedExecutionId}
              ORDER BY "createdAt" DESC
              LIMIT 30
            `),
            prisma.$queryRaw<Array<ToolAggRow>>(Prisma.sql`
              SELECT
                COALESCE(NULLIF("openclawToolName", ''), 'unknown') AS "toolName",
                COUNT(*)::int AS "calls",
                SUM(CASE WHEN LOWER(COALESCE("outcome", '')) = 'error' THEN 1 ELSE 0 END)::int AS "errors"
              FROM "TelemetryEvent"
              WHERE "category" = 'tool'
                AND ("traceId" = ${selectedExecutionId} OR "rootExecutionId" = ${selectedExecutionId})
              GROUP BY 1
              ORDER BY "calls" DESC
              LIMIT 25
            `),
            prisma.$queryRaw<Array<DomainAggRow>>(Prisma.sql`
              SELECT LOWER(o."value") AS "domain", COUNT(*)::int AS "calls"
              FROM "TelemetryObservable" o
              JOIN "TelemetryEvent" e ON e."id" = o."eventId"
              WHERE o."kind" = 'domain'
                AND e."category" = 'tool'
                AND (e."traceId" = ${selectedExecutionId} OR e."rootExecutionId" = ${selectedExecutionId})
              GROUP BY 1
              ORDER BY "calls" DESC
              LIMIT 25
            `),
            prisma.$queryRaw<Array<CorrelatedEventRow>>(Prisma.sql`
              SELECT
                e."id",
                e."ts",
                e."category",
                e."action",
                e."severity",
                e."outcome",
                e."outcomeReason",
                e."errorClass",
                e."errorCode",
                e."durationMs",
                e."openclawToolName",
                e."openclawToolCallId",
                e."payload",
                e."payloadRedacted"
              FROM "TelemetryEvent" e
              WHERE (e."traceId" = ${selectedExecutionId} OR e."rootExecutionId" = ${selectedExecutionId})
                AND e."category" IN ('tool', 'policy', 'session')
              ORDER BY e."ts" ASC, e."id" ASC
              LIMIT 280
            `),
          ]);

        return {
          trace,
          traceSpans,
          baseline: baselineRows[0] ?? null,
          decisions,
          tools,
          domains,
          correlatedEvents,
        };
      })()
    : {
        trace: null,
        traceSpans: [] as Awaited<ReturnType<typeof prisma.traceSpan.findMany>>,
        baseline: null as IntentBaselineRow | null,
        decisions: [] as IntentDecisionRow[],
        tools: [] as ToolAggRow[],
        domains: [] as DomainAggRow[],
        correlatedEvents: [] as CorrelatedEventRow[],
      };

  const reasonLines: string[] = [];
  if (selectedAlert) {
    const outcome = String(selectedAlert.eventOutcome || "").toLowerCase();
    const canonicalByOutcome: Record<string, string> = {
      block: `Blocked by policy rule: ${selectedAlert.ruleName}`,
      warn: `Warned by policy rule: ${selectedAlert.ruleName}`,
      modify: `Modified by policy rule: ${selectedAlert.ruleName}`,
      error: `Policy evaluation error on rule: ${selectedAlert.ruleName}`,
      allow: `Allowed by policy rule: ${selectedAlert.ruleName}`,
    };

    if (canonicalByOutcome[outcome]) {
      reasonLines.push(canonicalByOutcome[outcome]);
    } else {
      reasonLines.push(`${selectedAlert.ruleName} (${selectedAlert.ruleSeverity})`);
      if (selectedAlert.eventOutcome) reasonLines.push(`Policy outcome: ${selectedAlert.eventOutcome}`);
    }

    if (selectedAlert.ruleDescription) {
      const description = toPreview(selectedAlert.ruleDescription, 220);
      const descLower = description.toLowerCase();
      const redundantByOutcome =
        outcome &&
        descLower.includes("policy") &&
        (descLower.includes(outcome) ||
          (outcome === "block" && (descLower.includes("blocked") || descLower.includes("deny"))) ||
          (outcome === "warn" && (descLower.includes("warning") || descLower.includes("warned"))) ||
          (outcome === "modify" && (descLower.includes("sanitized") || descLower.includes("rewritten") || descLower.includes("modified"))) ||
          (outcome === "error" && (descLower.includes("failed") || descLower.includes("error"))) ||
          (outcome === "allow" && descLower.includes("allowed")));
      if (!redundantByOutcome) {
        reasonLines.push(description);
      }
    }

    if (selectedMeta?.alertType === "intent_drift") {
      reasonLines.push(`Drift score ${selectedMeta?.driftScore ?? detailData.baseline?.driftScore ?? 0} exceeded threshold`);
    }
    if (selectedMeta?.topTool) reasonLines.push(`Top offending tool: ${selectedMeta.topTool}`);
    if (selectedMeta?.topDomain) reasonLines.push(`Domain: ${selectedMeta.topDomain}`);
  }

  const correlatedTimeline: CorrelatedTimelineItem[] = [];
  if (detailData.baseline) {
    correlatedTimeline.push({
      key: "baseline",
      ts: detailData.baseline.updatedAt,
      event: "policy/intent_baseline · baseline_created",
      detail: detailData.baseline.taskBoundary || "Task boundary recorded",
      drift: detailData.baseline.driftScore ?? null,
      status: detailData.baseline.status || detailData.baseline.extractionMethod || "intent",
    });
  }

  const decisionAsc = [...detailData.decisions].sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
  for (const row of decisionAsc.slice(-14)) {
    const detail = [
      row.toolName ? `tool:${row.toolName}` : null,
      row.targetDomain ? `domain:${row.targetDomain}` : null,
      `drift ${row.driftScore} (${row.scoreDelta >= 0 ? "+" : ""}${row.scoreDelta})`,
      row.reason || null,
    ]
      .filter(Boolean)
      .join(" · ");
    correlatedTimeline.push({
      key: `decision-${row.id}`,
      ts: row.createdAt,
      event: `policy/intent_action_decision · decision:${row.action}`,
      detail,
      drift: row.driftScore,
      status: row.action,
    });
  }

  const toolLifecycle = detailData.correlatedEvents.filter((row) => row.category === "tool");
  const toolGroups = new Map<
    string,
    { ts: Date; tool: string; before?: CorrelatedEventRow; after?: CorrelatedEventRow; any: CorrelatedEventRow[] }
  >();
  for (const row of toolLifecycle) {
    const key = row.openclawToolCallId || `${row.openclawToolName || "unknown"}:${row.id}`;
    const existing = toolGroups.get(key);
    if (!existing) {
      toolGroups.set(key, {
        ts: row.ts,
        tool: row.openclawToolName || "unknown",
        before: row.action === "before_tool_call" ? row : undefined,
        after: row.action === "after_tool_call" ? row : undefined,
        any: [row],
      });
      continue;
    }
    existing.any.push(row);
    if (row.action === "before_tool_call") existing.before = row;
    if (row.action === "after_tool_call") existing.after = row;
  }
  const collapsedToolCalls = [...toolGroups.entries()]
    .map(([key, entry]) => ({ key, ...entry }))
    .sort((a, b) => a.ts.getTime() - b.ts.getTime())
    .slice(-12);

  for (const row of collapsedToolCalls) {
    const beforePreview = row.before ? pickToolPreview(row.before) : null;
    const afterOutcome = row.after?.outcome || row.after?.severity || "ok";
    const afterDuration = row.after?.durationMs;
    const afterReason = row.after?.outcomeReason || row.after?.errorCode || row.after?.errorClass;
    const detail = [
      beforePreview ? `call:${beforePreview}` : null,
      `result:${afterOutcome}`,
      typeof afterDuration === "number" ? `${afterDuration}ms` : null,
      afterReason || null,
    ]
      .filter(Boolean)
      .join(" · ");
    correlatedTimeline.push({
      key: `tool-${row.key}`,
      ts: row.ts,
      event: `tool:${row.tool} · tool_call`,
      detail,
      drift: null,
      status: String(afterOutcome),
    });
  }

  const significantPolicy = detailData.correlatedEvents.filter(
    (row) =>
      row.category === "policy" &&
      (String(row.outcome || "").toLowerCase() === "block" ||
        String(row.outcome || "").toLowerCase() === "error" ||
        String(row.severity || "").toLowerCase() === "error"),
  );
  for (const row of significantPolicy.slice(-6)) {
    const detail = [row.outcomeReason, row.errorCode, row.errorClass].filter(Boolean).join(" · ") || "policy evaluation event";
    correlatedTimeline.push({
      key: `policy-${row.id}`,
      ts: row.ts,
      event: `policy/${row.action} · policy_event`,
      detail,
      drift: null,
      status: row.outcome || row.severity,
    });
  }

  if (selectedAlert) {
    correlatedTimeline.push({
      key: `alert-${selectedAlert.id}`,
      ts: selectedAlert.ts,
      event: "alert · raised",
      detail: `${selectedAlert.eventCategory || "-"} / ${selectedAlert.eventAction || "-"} · ${selectedAlert.ruleName}`,
      drift: selectedMeta?.driftScore ?? null,
      status: selectedAlert.eventOutcome || selectedAlert.ruleSeverity,
    });
  }

  if (detailData.trace) {
    correlatedTimeline.push({
      key: "completion",
      ts: detailData.trace.endedAt || detailData.trace.lastEventTs,
      event: `execution · completion:${detailData.trace.status}`,
      detail: [
        typeof detailData.trace.durationMs === "number" ? `${detailData.trace.durationMs}ms` : null,
        `${detailData.trace.errorCount || 0} errors`,
        `${detailData.trace.blockCount || 0} blocks`,
      ]
        .filter(Boolean)
        .join(" · "),
      drift: null,
      status: detailData.trace.status,
    });
  }

  correlatedTimeline.sort((a, b) => a.ts.getTime() - b.ts.getTime());

  return (
    <AppShell
      activeNav="alerts"
      title="Security Alerts"
      subtitle="Triage and investigate policy, intent, and execution anomalies"
    >
      <div className="flex flex-col gap-4">
        <form method="get" className="rounded-xl border border-border bg-card/80 p-3">
          <div className="flex flex-col gap-2.5">
            <div className="flex flex-wrap items-center gap-2.5">
              <div className="relative max-w-sm flex-1">
                <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  name="q"
                  defaultValue={params.q ?? ""}
                  placeholder="Search alerts..."
                  className="h-9 pl-9"
                />
              </div>

              <select
                name="agentKey"
                defaultValue={params.agentKey ?? ""}
                className="h-9 min-w-[220px] rounded-md border border-border bg-card px-3 text-sm"
              >
                <option value="">All agents</option>
                {managedAgents.map((agent) => (
                  <option key={agent.agentKey} value={agent.agentKey}>
                    {agent.displayName || agent.reportedName || agent.agentInstanceId || agent.agentKey}
                  </option>
                ))}
              </select>

              {params.severity ? <input type="hidden" name="severity" value={params.severity} /> : null}
              {params.status ? <input type="hidden" name="status" value={params.status} /> : null}
              {params.alertType ? <input type="hidden" name="alertType" value={params.alertType} /> : null}
              {params.triggerType ? <input type="hidden" name="triggerType" value={params.triggerType} /> : null}
              {params.outcome ? <input type="hidden" name="outcome" value={params.outcome} /> : null}
              {params.ruleId ? <input type="hidden" name="ruleId" value={params.ruleId} /> : null}
              {params.requestId ? <input type="hidden" name="requestId" value={params.requestId} /> : null}
              {params.projectId ? <input type="hidden" name="projectId" value={params.projectId} /> : null}
              {params.minRisk ? <input type="hidden" name="minRisk" value={params.minRisk} /> : null}
              {params.alertModel ? <input type="hidden" name="alertModel" value={params.alertModel} /> : null}
              {params.includeLegacy === "1" ? <input type="hidden" name="includeLegacy" value="1" /> : null}
              {selectionMode ? <input type="hidden" name="select" value="1" /> : null}
              {focusMode ? <input type="hidden" name="focus" value="1" /> : null}
              {selectedAlert ? <input type="hidden" name="alertId" value={String(selectedAlert.id)} /> : null}

              <Button type="submit" size="sm" className="h-9">Apply</Button>
              {hasActiveFilters ? (
                <Link
                  href="/alerts"
                  className="inline-flex h-9 items-center gap-1 rounded-md border border-border px-2.5 text-xs text-muted-foreground transition-colors hover:text-foreground"
                >
                  <X className="h-3 w-3" />
                  Clear filters
                </Link>
              ) : null}
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="mr-1 text-xs text-muted-foreground">Severity:</span>
                <Link
                  href={hrefWith({ severity: null })}
                  className={`rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors ${
                    !params.severity
                      ? "border-primary/30 bg-primary/10 text-primary"
                      : "border-border text-muted-foreground hover:text-foreground"
                  }`}
                >
                  All
                </Link>
                {["critical", "high", "medium", "low"].map((value) => {
                  const active = params.severity === value;
                  return (
                    <Link
                      key={value}
                      href={hrefWith({ severity: active ? null : value })}
                      className={`rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors ${
                        active
                          ? "border-primary/30 bg-primary/10 text-primary"
                          : "border-border text-muted-foreground hover:text-foreground"
                      }`}
                    >
                      {value}
                    </Link>
                  );
                })}
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <span className="mr-1 text-xs text-muted-foreground">Status:</span>
                <Link
                  href={hrefWith({ status: null })}
                  className={`rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors ${
                    !params.status
                      ? "border-primary/30 bg-primary/10 text-primary"
                      : "border-border text-muted-foreground hover:text-foreground"
                  }`}
                >
                  All
                </Link>
                {["open", "acknowledged", "resolved", "false_positive"].map((value) => {
                  const active = params.status === value;
                  return (
                    <Link
                      key={value}
                      href={hrefWith({ status: active ? null : value })}
                      className={`rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors ${
                        active
                          ? "border-primary/30 bg-primary/10 text-primary"
                          : "border-border text-muted-foreground hover:text-foreground"
                      }`}
                    >
                      {value}
                    </Link>
                  );
                })}
              </div>

              <details className="group ml-auto" open={hasAdvancedFilters}>
                <summary className="flex cursor-pointer list-none items-center gap-1 rounded-md border border-border px-2.5 py-1.5 text-xs text-muted-foreground transition-colors hover:text-foreground">
                  Advanced filters
                  <ChevronRight className="h-3.5 w-3.5 transition-transform group-open:rotate-90" />
                </summary>
                <div className="mt-2 flex min-w-[680px] flex-col gap-2 rounded-lg border border-border/70 bg-card p-2.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="mr-1 text-xs text-muted-foreground">Type:</span>
                    <Link
                      href={hrefWith({ alertType: null })}
                      className={`rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors ${
                        !params.alertType
                          ? "border-primary/30 bg-primary/10 text-primary"
                          : "border-border text-muted-foreground hover:text-foreground"
                      }`}
                    >
                      All
                    </Link>
                    {["policy_block", "intent_drift", "tool_output_injection", "execution_error", "execution_anomaly"].map((value) => {
                      const active = params.alertType === value;
                      return (
                        <Link
                          key={value}
                          href={hrefWith({ alertType: active ? null : value })}
                          className={`rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors ${
                            active
                              ? "border-primary/30 bg-primary/10 text-primary"
                              : "border-border text-muted-foreground hover:text-foreground"
                          }`}
                        >
                          {value}
                        </Link>
                      );
                    })}
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    <span className="mr-1 text-xs text-muted-foreground">Trigger:</span>
                    <Link
                      href={hrefWith({ triggerType: null })}
                      className={`rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors ${
                        !params.triggerType
                          ? "border-primary/30 bg-primary/10 text-primary"
                          : "border-border text-muted-foreground hover:text-foreground"
                      }`}
                    >
                      All
                    </Link>
                    {["user", "cron", "webhook", "retry", "system"].map((value) => {
                      const active = params.triggerType === value;
                      return (
                        <Link
                          key={value}
                          href={hrefWith({ triggerType: active ? null : value })}
                          className={`rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors ${
                            active
                              ? "border-primary/30 bg-primary/10 text-primary"
                              : "border-border text-muted-foreground hover:text-foreground"
                          }`}
                        >
                          {value}
                        </Link>
                      );
                    })}
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    <span className="mr-1 text-xs text-muted-foreground">Outcome:</span>
                    <Link
                      href={hrefWith({ outcome: null })}
                      className={`rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors ${
                        !params.outcome
                          ? "border-primary/30 bg-primary/10 text-primary"
                          : "border-border text-muted-foreground hover:text-foreground"
                      }`}
                    >
                      All
                    </Link>
                    {["allow", "warn", "modify", "block", "error"].map((value) => {
                      const active = params.outcome === value;
                      return (
                        <Link
                          key={value}
                          href={hrefWith({ outcome: active ? null : value })}
                          className={`rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors ${
                            active
                              ? "border-primary/30 bg-primary/10 text-primary"
                              : "border-border text-muted-foreground hover:text-foreground"
                          }`}
                        >
                          {value}
                        </Link>
                      );
                    })}
                  </div>

                  <div className="flex items-center gap-2 pt-1">
                    <span className="text-xs text-muted-foreground">Limit</span>
                    <Input name="limit" defaultValue={String(safeLimit)} className="h-8 w-[90px]" />
                  </div>
                </div>
              </details>
            </div>
          </div>
        </form>

        <form id="bulk-alert-selected" action={bulkAlertTransitionAction}>
          <input type="hidden" name="returnTo" value={returnTo} />
        </form>

        <div className={focusMode ? "grid gap-4" : "grid gap-4 xl:grid-cols-[420px_minmax(0,1fr)]"}>
          {!focusMode ? (
            <aside className="overflow-hidden rounded-xl border border-border bg-card/80">
            <div className="flex items-center justify-between border-b border-border px-4 py-3">
              <div>
                <h2 className="text-sm font-semibold text-foreground">Alert groups</h2>
                <p className="text-xs text-muted-foreground">
                  {alerts.length} shown / {totalAlerts} total
                </p>
              </div>
              <div className="flex items-center gap-1.5">
                {selectionMode ? (
                  <>
                    <Button
                      type="submit"
                      form="bulk-alert-selected"
                      size="sm"
                      variant="outline"
                      className="h-7 px-2 text-[11px]"
                      name="nextStatus"
                      value="open"
                    >
                      Unack selected
                    </Button>
                    <Button
                      type="submit"
                      form="bulk-alert-selected"
                      size="sm"
                      variant="outline"
                      className="h-7 px-2 text-[11px]"
                      name="nextStatus"
                      value="acknowledged"
                    >
                      ACK selected
                    </Button>
                    <Button
                      type="submit"
                      form="bulk-alert-selected"
                      size="sm"
                      variant="outline"
                      className="h-7 px-2 text-[11px]"
                      name="nextStatus"
                      value="resolved"
                    >
                      Close selected
                    </Button>
                    <Button size="sm" variant="ghost" className="h-7 px-2 text-[11px]" asChild>
                      <Link href={doneHref}>Done</Link>
                    </Button>
                  </>
                ) : (
                  <Button size="sm" variant="outline" className="h-7 px-2 text-[11px]" asChild>
                    <Link href={selectHref}>Select</Link>
                  </Button>
                )}
              </div>
            </div>

            <div className="max-h-[calc(100vh-270px)] overflow-y-auto p-2">
              {groups.length === 0 ? (
                <div className="rounded-lg border border-dashed border-border px-3 py-6 text-center text-sm text-muted-foreground">
                  No alerts for current filters.
                </div>
              ) : (
                groups.map((group) => {
                  const defaultOpen = selectedGroupKey === group.rootKey || group.openCount > 0;
                  return (
                    <details key={group.rootKey} open={defaultOpen} className="mb-2 overflow-hidden rounded-lg border border-border/70 bg-card">
                      <summary className="flex cursor-pointer list-none items-center justify-between gap-2 px-3 py-2 text-xs text-muted-foreground hover:bg-muted/25">
                        <div className="flex items-center gap-2">
                          <ChevronRight className="h-3.5 w-3.5" />
                          <span className="font-mono text-[11px] text-foreground">{compactGroupId(group.rootKey)}</span>
                          <Badge className={severityBadgeClass(group.maxSeverity)}>{group.maxSeverity}</Badge>
                          {group.openCount > 0 ? <Badge variant="destructive">{group.openCount} open</Badge> : null}
                        </div>
                        <span>{formatDate(group.latestTs)}</span>
                      </summary>

                      <div className="divide-y divide-border/60">
                        {group.alerts.map((alert) => {
                          const status = toStatusText(alert.status);
                          const isTerminal = status === "resolved" || status === "false_positive";
                          const agentLabel =
                            (alert.agentInstanceId ? managedNames.get(alert.agentInstanceId) : undefined) ||
                            alert.openclawAgentId ||
                            alert.agentInstanceId ||
                            "-";
                          const alertMeta = alert as AlertRecord & {
                            alertType?: string | null;
                            triggerType?: string | null;
                            topTool?: string | null;
                            topDomain?: string | null;
                            driftScore?: number | null;
                          };

                          return (
                            <div key={alert.id} className={`flex items-start gap-2 px-3 py-2 ${selectedAlert?.id === alert.id ? "bg-muted/30" : ""}`}>
                              {selectionMode ? (
                                <input
                                  type="checkbox"
                                  name="ids"
                                  value={String(alert.id)}
                                  form="bulk-alert-selected"
                                  className="mt-1 h-3.5 w-3.5 rounded border-border"
                                  aria-label={`select alert ${alert.id}`}
                                />
                              ) : null}

                              <Link href={hrefWith({ alertId: String(alert.id) })} className="min-w-0 flex-1 space-y-1">
                                <div className="flex items-center gap-1.5">
                                  <Badge className={severityBadgeClass(alert.ruleSeverity)}>{alert.ruleSeverity}</Badge>
                                  <Badge className={statusBadgeClass(status)}>{status}</Badge>
                                  {alertMeta.alertType ? (
                                    <Badge className={alertTypeBadgeClass(alertMeta.alertType)}>{alertMeta.alertType}</Badge>
                                  ) : null}
                                </div>
                                <div className="truncate text-xs font-medium text-foreground">{alert.ruleName}</div>
                                <div className="truncate text-[11px] text-muted-foreground">
                                  {agentLabel} · {alert.eventCategory || "-"}/{alert.eventAction || "-"}
                                </div>
                                <div className="truncate text-[11px] text-muted-foreground">{formatDate(alert.ts)}</div>
                              </Link>

                              <div className="mt-0.5 flex shrink-0 items-center gap-1">
                                {!isTerminal && status === "open" ? (
                                  <form action={bulkAlertTransitionAction}>
                                    <input type="hidden" name="returnTo" value={returnTo} />
                                    <input type="hidden" name="ids" value={String(alert.id)} />
                                    <Button type="submit" size="sm" variant="outline" className="h-6 px-2 text-[11px]" name="nextStatus" value="acknowledged">
                                      ACK
                                    </Button>
                                  </form>
                                ) : null}
                                {!isTerminal && status === "acknowledged" ? (
                                  <form action={bulkAlertTransitionAction}>
                                    <input type="hidden" name="returnTo" value={returnTo} />
                                    <input type="hidden" name="ids" value={String(alert.id)} />
                                    <Button type="submit" size="sm" variant="outline" className="h-6 px-2 text-[11px]" name="nextStatus" value="open">
                                      Unack
                                    </Button>
                                  </form>
                                ) : null}
                                {!isTerminal ? (
                                  <form action={bulkAlertTransitionAction}>
                                    <input type="hidden" name="returnTo" value={returnTo} />
                                    <input type="hidden" name="ids" value={String(alert.id)} />
                                    <Button type="submit" size="sm" variant="outline" className="h-6 px-2 text-[11px]" name="nextStatus" value="resolved">
                                      Close
                                    </Button>
                                  </form>
                                ) : null}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </details>
                  );
                })
              )}
            </div>
            </aside>
          ) : null}

          <section className="overflow-hidden rounded-xl border border-border bg-card/80">
            {!selectedAlert ? (
              <div className="flex min-h-[520px] items-center justify-center px-6 text-center text-sm text-muted-foreground">
                Select an alert to investigate.
              </div>
            ) : (
              <>
                <div className="max-h-[calc(100vh-300px)] overflow-y-auto p-4">
                <div className="rounded-xl border border-border bg-card p-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="space-y-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge className={severityBadgeClass(selectedAlert.ruleSeverity)}>{selectedAlert.ruleSeverity}</Badge>
                        <Badge className={statusBadgeClass(selectedAlert.status)}>{toStatusText(selectedAlert.status)}</Badge>
                        {selectedMeta?.alertType ? <Badge className={alertTypeBadgeClass(selectedMeta.alertType)}>{selectedMeta.alertType}</Badge> : null}
                        {selectedMeta?.triggerType ? <Badge variant="outline">{selectedMeta.triggerType}</Badge> : null}
                        {selectedAlert.eventOutcome ? <Badge className={outcomeBadgeClass(selectedAlert.eventOutcome)}>{selectedAlert.eventOutcome}</Badge> : null}
                      </div>
                      <h2 className="text-base font-semibold text-foreground">{selectedAlert.ruleName}</h2>
                      <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                        <span>Alert #{selectedAlert.id}</span>
                        <span>{formatDate(selectedAlert.ts)}</span>
                        <span className="font-mono">req:{selectedAlert.requestId || "-"}</span>
                        {selectedExecutionId ? (
                          <Link
                            href={`/executions?focusExecutionId=${encodeURIComponent(selectedExecutionId)}`}
                            className="inline-flex items-center gap-1 font-mono text-primary hover:underline"
                          >
                            {shortId(selectedExecutionId, 22)}
                            <ExternalLink className="h-3 w-3" />
                          </Link>
                        ) : null}
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <Button size="sm" variant="ghost" asChild>
                        <Link href={focusHref}>{focusMode ? "Show list" : "Focus"}</Link>
                      </Button>
                      {toStatusText(selectedAlert.status) === "open" ? (
                        <form action={bulkAlertTransitionAction}>
                          <input type="hidden" name="returnTo" value={returnTo} />
                          <input type="hidden" name="ids" value={String(selectedAlert.id)} />
                          <Button type="submit" size="sm" variant="outline" name="nextStatus" value="acknowledged">
                            <CheckCheck className="mr-1 h-3.5 w-3.5" />
                            ACK
                          </Button>
                        </form>
                      ) : null}
                      {toStatusText(selectedAlert.status) === "acknowledged" ? (
                        <form action={bulkAlertTransitionAction}>
                          <input type="hidden" name="returnTo" value={returnTo} />
                          <input type="hidden" name="ids" value={String(selectedAlert.id)} />
                          <Button type="submit" size="sm" variant="outline" name="nextStatus" value="open">
                            Unack
                          </Button>
                        </form>
                      ) : null}

                      {(toStatusText(selectedAlert.status) === "open" || toStatusText(selectedAlert.status) === "acknowledged") ? (
                        <Button size="sm" variant="outline" asChild>
                          <Link href="#resolution">Resolve</Link>
                        </Button>
                      ) : null}

                    </div>
                  </div>
                </div>

                <div className="mt-4 rounded-xl border border-border bg-card p-4">
                  <h3 className="text-sm font-semibold text-foreground">Why this alert triggered</h3>
                  <ul className="mt-3 space-y-1.5 text-sm text-muted-foreground">
                    {reasonLines.length ? (
                      reasonLines.map((line, idx) => (
                        <li key={`${line}-${idx}`} className="flex items-start gap-2">
                          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 text-yellow-400" />
                          <span>{line}</span>
                        </li>
                      ))
                    ) : (
                      <li className="text-muted-foreground">No additional explanation available.</li>
                    )}
                  </ul>
                </div>

                <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
                  <div className="rounded-xl border border-border bg-card p-4">
                    <h3 className="text-sm font-semibold text-foreground">Execution context</h3>
                    <div className="mt-3 grid grid-cols-2 gap-3 text-sm">
                      <div>
                        <p className="text-xs uppercase tracking-wide text-muted-foreground">Trigger</p>
                        <p className="mt-1 text-foreground">{selectedMeta?.triggerType || "-"}</p>
                      </div>
                      <div>
                        <p className="text-xs uppercase tracking-wide text-muted-foreground">Execution status</p>
                        <p className="mt-1 text-foreground">{detailData.trace?.status || "-"}</p>
                      </div>
                      <div>
                        <p className="text-xs uppercase tracking-wide text-muted-foreground">Drift score</p>
                        <p className="mt-1 text-foreground">{selectedMeta?.driftScore ?? detailData.baseline?.driftScore ?? "-"}</p>
                      </div>
                      <div>
                        <p className="text-xs uppercase tracking-wide text-muted-foreground">Span count</p>
                        <p className="mt-1 text-foreground">{detailData.traceSpans.length}</p>
                      </div>
                      <div>
                        <p className="text-xs uppercase tracking-wide text-muted-foreground">Tool calls</p>
                        <p className="mt-1 text-foreground">{detailData.tools.reduce((acc, row) => acc + row.calls, 0)}</p>
                      </div>
                      <div>
                        <p className="text-xs uppercase tracking-wide text-muted-foreground">Domains touched</p>
                        <p className="mt-1 text-foreground">{detailData.domains.length}</p>
                      </div>
                    </div>
                    <div className="mt-4 flex flex-wrap items-center gap-2">
                      {selectedAlert.requestId ? (
                        <Button size="sm" variant="outline" asChild>
                          <Link href={`/events?requestId=${encodeURIComponent(selectedAlert.requestId)}`}>Events</Link>
                        </Button>
                      ) : null}
                      {selectedExecutionId ? (
                        <Button size="sm" variant="outline" asChild>
                          <Link href={`/traces?traceId=${encodeURIComponent(selectedExecutionId)}`}>Traces</Link>
                        </Button>
                      ) : null}
                    </div>
                  </div>

                  <div className="rounded-xl border border-border bg-card p-4">
                    <h3 className="text-sm font-semibold text-foreground">Intent baseline</h3>
                    {detailData.baseline ? (
                      <div className="mt-3 space-y-2 text-sm text-muted-foreground">
                        <div>
                          Boundary: <span className="text-foreground">{detailData.baseline.taskBoundary || "-"}</span>
                        </div>
                        <div>
                          Scopes: <span className="text-foreground">{toStringArray(detailData.baseline.expectedScopes).join(", ") || "-"}</span>
                        </div>
                        <div>
                          Domains: <span className="text-foreground">{toStringArray(detailData.baseline.expectedDomains).join(", ") || "-"}</span>
                        </div>
                        <div>
                          Method: <span className="text-foreground">{detailData.baseline.extractionMethod || "-"}</span>
                        </div>
                      </div>
                    ) : (
                      <p className="mt-3 text-sm text-muted-foreground">No execution intent baseline available.</p>
                    )}
                  </div>
                </div>

                <details className="group mt-4 rounded-xl border border-border bg-card p-4">
                  <summary className="flex cursor-pointer list-none items-center justify-between gap-2 rounded-md px-1 py-1 text-sm font-semibold text-foreground hover:bg-muted/20">
                    <span>Timeline</span>
                    <ChevronRight className="h-4 w-4 text-muted-foreground transition-transform group-open:rotate-90" />
                  </summary>
                  {correlatedTimeline.length ? (
                    <div className="mt-3 overflow-x-auto rounded-lg border border-border/70">
                      <div className="grid min-w-[900px] grid-cols-[170px_minmax(0,1fr)_90px_130px] border-b border-border/70 px-3 py-2 text-[11px] uppercase tracking-wide text-muted-foreground">
                        <div>Time</div>
                        <div>Event</div>
                        <div>Drift</div>
                        <div>Status</div>
                      </div>
                      {correlatedTimeline.map((item) => (
                        <div
                          key={item.key}
                          className="grid min-w-[900px] grid-cols-[170px_minmax(0,1fr)_90px_130px] items-start gap-3 border-b border-border/60 px-3 py-2 text-xs last:border-b-0"
                        >
                          <div className="text-muted-foreground">{formatDate(item.ts)}</div>
                          <div className="min-w-0">
                            <div className="font-medium text-foreground">{item.event}</div>
                            <div className="truncate text-muted-foreground">{item.detail}</div>
                          </div>
                          <div className="text-foreground">{typeof item.drift === "number" ? item.drift : "-"}</div>
                          <div>
                            {item.status ? <Badge className={outcomeBadgeClass(item.status)}>{item.status}</Badge> : <span className="text-muted-foreground">-</span>}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="mt-3 text-sm text-muted-foreground">No correlated timeline events available.</p>
                  )}
                </details>

                <details className="group mt-4 rounded-xl border border-border bg-card p-4">
                  <summary className="flex cursor-pointer list-none items-center justify-between gap-2 rounded-md px-1 py-1 text-sm font-semibold text-foreground hover:bg-muted/20">
                    <span>Tool and domain review</span>
                    <ChevronRight className="h-4 w-4 text-muted-foreground transition-transform group-open:rotate-90" />
                  </summary>
                  <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-2">
                    <div>
                      <p className="text-xs uppercase tracking-wide text-muted-foreground">Top tools</p>
                      <div className="mt-2 space-y-1.5">
                        {detailData.tools.length ? (
                          detailData.tools.map((row) => (
                            <div key={row.toolName} className="flex items-center justify-between rounded-md border border-border/70 px-2.5 py-1.5 text-xs">
                              <span className="text-foreground">{row.toolName}</span>
                              <span className="text-muted-foreground">{row.calls} calls · {row.errors} errors</span>
                            </div>
                          ))
                        ) : (
                          <p className="text-sm text-muted-foreground">No tool activity.</p>
                        )}
                      </div>
                    </div>
                    <div>
                      <p className="text-xs uppercase tracking-wide text-muted-foreground">Domains touched</p>
                      <div className="mt-2 space-y-1.5">
                        {detailData.domains.length ? (
                          detailData.domains.map((row) => (
                            <div key={row.domain} className="flex items-center justify-between rounded-md border border-border/70 px-2.5 py-1.5 text-xs">
                              <span className="text-foreground">{row.domain}</span>
                              <span className="text-muted-foreground">{row.calls}</span>
                            </div>
                          ))
                        ) : (
                          <p className="text-sm text-muted-foreground">No domain activity.</p>
                        )}
                      </div>
                    </div>
                  </div>
                </details>
                </div>

                <div id="resolution" className="border-t border-border bg-card px-4 py-3">
                  <h3 className="text-sm font-semibold text-foreground">Resolution</h3>
                  <form action={resolveAlertAction} className="mt-3 grid grid-cols-1 gap-3 lg:grid-cols-[180px_220px_1fr_auto]">
                    <input type="hidden" name="id" value={selectedAlert.id} />
                    <input type="hidden" name="returnTo" value={returnTo} />

                    <select name="nextStatus" defaultValue="resolved" className="h-9 rounded-md border border-border bg-card px-3 text-sm">
                      <option value="resolved">resolved</option>
                      <option value="false_positive">false_positive</option>
                    </select>

                    <select
                      name="classification"
                      defaultValue={(selectedMeta?.classification as AlertClassification | undefined) || "benign_anomaly"}
                      className="h-9 rounded-md border border-border bg-card px-3 text-sm"
                    >
                      <option value="malicious_input">malicious_input</option>
                      <option value="capability_abuse">capability_abuse</option>
                      <option value="policy_misconfig">policy_misconfig</option>
                      <option value="agent_bug">agent_bug</option>
                      <option value="benign_anomaly">benign_anomaly</option>
                    </select>

                    <Input
                      name="resolutionNote"
                      defaultValue={selectedMeta?.resolutionNote || ""}
                      placeholder="Resolution note (required, min 8 chars)"
                      className="h-9"
                    />

                    <Button type="submit" size="sm" className="h-9">
                      <ShieldAlert className="mr-1 h-3.5 w-3.5" />
                      Save
                    </Button>
                  </form>
                  {selectedMeta?.resolutionNote ? (
                    <p className="mt-2 text-xs text-muted-foreground">Last note: {selectedMeta.resolutionNote}</p>
                  ) : null}
                </div>
              </>
            )}
          </section>
        </div>
      </div>
    </AppShell>
  );
}
