/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/alerts/execution-risk.ts.
 */
import { Prisma } from "@prisma/client";

export type ExecutionAlertCategory =
  | "policy_violation"
  | "intent_drift"
  | "output_injection"
  | "runtime_failure"
  | "capability_escalation";

export type ExecutionBreachLevel = "warn" | "high" | "critical";

export type ExecutionRiskSignal = {
  ts: Date;
  eventId: string;
  spanId?: string | null;
  executionId: string;
  rootExecutionId?: string | null;
  projectId?: string | null;
  agentInstanceId?: string | null;
  openclawAgentId?: string | null;
  openclawSessionKey?: string | null;
  requestId?: string | null;
  triggerType?: string | null;
  category: ExecutionAlertCategory;
  alertType: string;
  ruleId: string;
  ruleName: string;
  ruleCategory: string;
  ruleDescription?: string | null;
  ruleSeverity: string;
  eventCategory?: string | null;
  eventAction?: string | null;
  eventOutcome?: string | null;
  outcomeReason?: string | null;
  riskScore?: number | null;
  driftScore?: number | null;
  toolName?: string | null;
  domain?: string | null;
};

type RiskStateLike = {
  driftScore?: number | null;
  blockCount?: number | null;
  warnCount?: number | null;
  modifyCount?: number | null;
  errorCount?: number | null;
  sanitizationCount?: number | null;
  lastBreachLevel?: string | null;
};

type Bucket = {
  executionId: string;
  rootExecutionId: string | null;
  projectId: string | null;
  agentInstanceId: string | null;
  openclawAgentId: string | null;
  openclawSessionKey: string | null;
  requestId: string | null;
  triggerType: string | null;
  category: ExecutionAlertCategory;
  firstTs: Date;
  lastTs: Date;
  maxRisk: number;
  maxDrift: number;
  blockCount: number;
  warnCount: number;
  modifyCount: number;
  errorCount: number;
  sanitizationCount: number;
  signalCount: number;
  sampleEventIds: string[];
  sampleSpanIds: string[];
  tools: Map<string, number>;
  domains: Map<string, number>;
  sourceAlertTypes: Map<string, number>;
};

const BREACH_RANK: Record<ExecutionBreachLevel, number> = {
  warn: 1,
  high: 2,
  critical: 3,
};

function toLower(value: string | null | undefined): string {
  return String(value || "").trim().toLowerCase();
}

function categoryRuleName(category: ExecutionAlertCategory): string {
  switch (category) {
    case "policy_violation":
      return "Execution policy violation";
    case "intent_drift":
      return "Execution intent drift";
    case "output_injection":
      return "Execution output injection";
    case "runtime_failure":
      return "Execution runtime failure";
    case "capability_escalation":
      return "Execution capability escalation";
    default:
      return "Execution incident";
  }
}

function categoryAlertType(category: ExecutionAlertCategory): string {
  switch (category) {
    case "policy_violation":
      return "policy_block";
    case "intent_drift":
      return "intent_drift";
    case "output_injection":
      return "tool_output_injection";
    case "runtime_failure":
      return "execution_error";
    case "capability_escalation":
      return "execution_anomaly";
    default:
      return "execution_anomaly";
  }
}

function severityFromBreach(level: ExecutionBreachLevel): "medium" | "high" | "critical" {
  if (level === "warn") return "medium";
  if (level === "high") return "high";
  return "critical";
}

function maxSeverityForLevel(level: ExecutionBreachLevel | null): "low" | "medium" | "high" | "critical" {
  if (!level) return "low";
  return severityFromBreach(level);
}

function parseBreachLevel(raw?: string | null): ExecutionBreachLevel | null {
  const value = toLower(raw);
  if (value === "warn" || value === "high" || value === "critical") return value;
  return null;
}

function breachRank(raw?: string | null): number {
  const parsed = parseBreachLevel(raw);
  if (!parsed) return 0;
  return BREACH_RANK[parsed];
}

function pickTop(map: Map<string, number>): string | null {
  let best: string | null = null;
  let bestCount = -1;
  for (const [key, count] of map.entries()) {
    if (count > bestCount) {
      best = key;
      bestCount = count;
    }
  }
  return best;
}

function addFreq(map: Map<string, number>, value?: string | null) {
  const key = String(value || "").trim();
  if (!key) return;
  map.set(key, (map.get(key) || 0) + 1);
}

function normalizeOutcome(outcome?: string | null): string {
  const raw = toLower(outcome);
  if (!raw) return "unknown";
  if (raw === "blocked") return "block";
  if (raw === "warning") return "warn";
  if (raw === "ok" || raw === "success" || raw === "submitted") return "allow";
  if (raw === "failed" || raw === "fail") return "error";
  return raw;
}

function deriveBreachLevel(state: RiskStateLike): ExecutionBreachLevel | null {
  const drift = Number(state.driftScore || 0);
  const blocks = Number(state.blockCount || 0);
  const warns = Number(state.warnCount || 0);
  const modifies = Number(state.modifyCount || 0);
  const errors = Number(state.errorCount || 0);
  const sanitizations = Number(state.sanitizationCount || 0);

  if (drift >= 95 || blocks >= 5 || errors >= 3) return "critical";
  if (blocks >= 1 || errors >= 1 || drift >= 80) return "high";
  if (warns >= 1 || modifies >= 1 || sanitizations >= 1 || drift >= 40) return "warn";
  return null;
}

function deriveStatus(level: ExecutionBreachLevel | null): string {
  if (level === "critical") return "critical";
  if (level === "high") return "high";
  if (level === "warn") return "elevated";
  return "normal";
}

function deriveEventOutcome(agg: Bucket, level: ExecutionBreachLevel): string {
  if (agg.blockCount > 0 || level === "high" || level === "critical") return "block";
  if (agg.errorCount > 0) return "error";
  if (agg.modifyCount > 0 || agg.sanitizationCount > 0) return "modify";
  if (agg.warnCount > 0 || level === "warn") return "warn";
  return "warn";
}

function deriveRuleDescription(agg: Bucket): string {
  const parts = [
    `${agg.signalCount} risk signals`,
    `${agg.blockCount} blocks`,
    `${agg.warnCount} warns`,
    `${agg.errorCount} errors`,
    `${agg.sanitizationCount} sanitizations`,
    `max drift ${agg.maxDrift}`,
  ];
  return parts.join(" · ");
}

function bucketKey(executionId: string, category: ExecutionAlertCategory): string {
  return `${executionId}::${category}`;
}

/**
 * Aggregates raw risk signals into execution/category buckets.
 *
 * Buckets preserve first/last timestamps, severity counters, and sample evidence so
 * downstream alert creation emits a single incident-level alert per execution stage
 * instead of noisy per-event alerts.
 */
function toBucket(signals: ExecutionRiskSignal[]): Map<string, Bucket> {
  const out = new Map<string, Bucket>();
  for (const signal of signals) {
    const key = bucketKey(signal.executionId, signal.category);
    const normalizedOutcome = normalizeOutcome(signal.eventOutcome);
    const drift = Number.isFinite(Number(signal.driftScore)) ? Number(signal.driftScore) : 0;
    const risk = Number.isFinite(Number(signal.riskScore)) ? Number(signal.riskScore) : 0;
    const existing = out.get(key);
    if (!existing) {
      const bucket: Bucket = {
        executionId: signal.executionId,
        rootExecutionId: signal.rootExecutionId || signal.executionId,
        projectId: signal.projectId || null,
        agentInstanceId: signal.agentInstanceId || null,
        openclawAgentId: signal.openclawAgentId || null,
        openclawSessionKey: signal.openclawSessionKey || null,
        requestId: signal.requestId || null,
        triggerType: signal.triggerType || null,
        category: signal.category,
        firstTs: signal.ts,
        lastTs: signal.ts,
        maxRisk: risk,
        maxDrift: drift,
        blockCount: normalizedOutcome === "block" ? 1 : 0,
        warnCount: normalizedOutcome === "warn" ? 1 : 0,
        modifyCount: normalizedOutcome === "modify" ? 1 : 0,
        errorCount: normalizedOutcome === "error" ? 1 : 0,
        sanitizationCount:
          signal.category === "output_injection" && (normalizedOutcome === "modify" || normalizedOutcome === "block" || normalizedOutcome === "warn")
            ? 1
            : 0,
        signalCount: 1,
        sampleEventIds: signal.eventId ? [signal.eventId] : [],
        sampleSpanIds: signal.spanId ? [signal.spanId] : [],
        tools: new Map<string, number>(),
        domains: new Map<string, number>(),
        sourceAlertTypes: new Map<string, number>(),
      };
      addFreq(bucket.tools, signal.toolName);
      addFreq(bucket.domains, signal.domain);
      addFreq(bucket.sourceAlertTypes, signal.alertType);
      out.set(key, bucket);
      continue;
    }

    existing.signalCount += 1;
    if (signal.ts < existing.firstTs) existing.firstTs = signal.ts;
    if (signal.ts > existing.lastTs) existing.lastTs = signal.ts;
    if (risk > existing.maxRisk) existing.maxRisk = risk;
    if (drift > existing.maxDrift) existing.maxDrift = drift;
    if (normalizedOutcome === "block") existing.blockCount += 1;
    if (normalizedOutcome === "warn") existing.warnCount += 1;
    if (normalizedOutcome === "modify") existing.modifyCount += 1;
    if (normalizedOutcome === "error") existing.errorCount += 1;
    if (
      signal.category === "output_injection" &&
      (normalizedOutcome === "modify" || normalizedOutcome === "block" || normalizedOutcome === "warn")
    ) {
      existing.sanitizationCount += 1;
    }
    if (signal.eventId && existing.sampleEventIds.length < 12 && !existing.sampleEventIds.includes(signal.eventId)) {
      existing.sampleEventIds.push(signal.eventId);
    }
    if (signal.spanId && existing.sampleSpanIds.length < 12 && !existing.sampleSpanIds.includes(signal.spanId)) {
      existing.sampleSpanIds.push(signal.spanId);
    }
    addFreq(existing.tools, signal.toolName);
    addFreq(existing.domains, signal.domain);
    addFreq(existing.sourceAlertTypes, signal.alertType);
  }
  return out;
}

/**
 * Normalizes mixed legacy/current alert attributes into execution alert categories.
 *
 * @param input Source alert/event metadata.
 * @returns Canonical execution-level category used by aggregation + UI.
 */
export function mapExecutionAlertCategory(input: {
  alertType?: string | null;
  eventCategory?: string | null;
  eventOutcome?: string | null;
  ruleCategory?: string | null;
  ruleId?: string | null;
}): ExecutionAlertCategory {
  const alertType = toLower(input.alertType);
  const eventCategory = toLower(input.eventCategory);
  const eventOutcome = toLower(input.eventOutcome);
  const ruleCategory = toLower(input.ruleCategory);
  const ruleId = toLower(input.ruleId);

  if (alertType === "intent_drift" || ruleCategory.includes("intent") || ruleId.includes("intent")) {
    return "intent_drift";
  }
  if (alertType === "tool_output_injection" || ruleCategory.includes("prompt") || ruleCategory.includes("injection") || ruleId.includes("injection")) {
    return "output_injection";
  }
  if (alertType === "execution_error" || eventOutcome === "error" || ruleId.includes("runtime.error") || ruleId.includes("run-failure")) {
    return "runtime_failure";
  }
  if (alertType === "policy_block" || eventCategory === "policy" || eventOutcome === "block" || eventOutcome === "warn" || eventOutcome === "modify") {
    return "policy_violation";
  }
  return "capability_escalation";
}

/**
 * Builds execution-level risk alerts from event-level risk signals.
 *
 * The function updates `ExecutionRiskState` and emits alerts only on breach escalation,
 * enforcing the "one alert per execution/category/breach-level" model.
 *
 * @param tx Prisma transaction client used by telemetry ingest.
 * @param signals Risk signals extracted from detections/policy outcomes.
 * @returns Batched `ThreatAlert` rows ready for `createMany`.
 */
export async function buildExecutionRiskAlerts(
  tx: Prisma.TransactionClient,
  signals: ExecutionRiskSignal[],
): Promise<Prisma.ThreatAlertCreateManyInput[]> {
  if (!signals.length) return [];

  const buckets = toBucket(signals);
  if (!buckets.size) return [];

  const identityKeys = [...buckets.values()].map((bucket) => ({
    executionId: bucket.executionId,
    category: bucket.category,
  }));

  const existingRows = await tx.executionRiskState.findMany({
    where: { OR: identityKeys.map((item) => ({ executionId: item.executionId, category: item.category })) },
  });
  const existingMap = new Map<string, (typeof existingRows)[number]>();
  for (const row of existingRows) {
    existingMap.set(bucketKey(row.executionId, row.category as ExecutionAlertCategory), row);
  }

  const alerts: Prisma.ThreatAlertCreateManyInput[] = [];

  for (const bucket of buckets.values()) {
    const key = bucketKey(bucket.executionId, bucket.category);
    const prev = existingMap.get(key);
    const next = {
      driftScore: Math.max(Number(prev?.driftScore || 0), bucket.maxDrift),
      blockCount: Number(prev?.blockCount || 0) + bucket.blockCount,
      warnCount: Number(prev?.warnCount || 0) + bucket.warnCount,
      modifyCount: Number(prev?.modifyCount || 0) + bucket.modifyCount,
      errorCount: Number(prev?.errorCount || 0) + bucket.errorCount,
      sanitizationCount: Number(prev?.sanitizationCount || 0) + bucket.sanitizationCount,
      signalCount: Number(prev?.signalCount || 0) + bucket.signalCount,
    };
    const prevBreach = parseBreachLevel(prev?.lastBreachLevel);
    const nextBreach = deriveBreachLevel(next);
    const isEscalation = breachRank(nextBreach) > breachRank(prevBreach);

    await tx.executionRiskState.upsert({
      where: {
        executionId_category: {
          executionId: bucket.executionId,
          category: bucket.category,
        },
      },
      create: {
        executionId: bucket.executionId,
        rootExecutionId: bucket.rootExecutionId,
        projectId: bucket.projectId,
        agentInstanceId: bucket.agentInstanceId,
        openclawAgentId: bucket.openclawAgentId,
        triggerType: bucket.triggerType,
        category: bucket.category,
        status: deriveStatus(nextBreach),
        maxSeverity: maxSeverityForLevel(nextBreach),
        driftScore: next.driftScore,
        blockCount: next.blockCount,
        warnCount: next.warnCount,
        modifyCount: next.modifyCount,
        errorCount: next.errorCount,
        sanitizationCount: next.sanitizationCount,
        signalCount: next.signalCount,
        firstSignalAt: prev?.firstSignalAt || bucket.firstTs,
        lastSignalAt: bucket.lastTs,
        lastEventId: bucket.sampleEventIds.at(-1) || null,
        lastSpanId: bucket.sampleSpanIds.at(-1) || null,
        lastBreachLevel: nextBreach || null,
      },
      update: {
        rootExecutionId: bucket.rootExecutionId || prev?.rootExecutionId || null,
        projectId: bucket.projectId || prev?.projectId || null,
        agentInstanceId: bucket.agentInstanceId || prev?.agentInstanceId || null,
        openclawAgentId: bucket.openclawAgentId || prev?.openclawAgentId || null,
        triggerType: bucket.triggerType || prev?.triggerType || null,
        status: deriveStatus(nextBreach),
        maxSeverity: maxSeverityForLevel(nextBreach),
        driftScore: next.driftScore,
        blockCount: next.blockCount,
        warnCount: next.warnCount,
        modifyCount: next.modifyCount,
        errorCount: next.errorCount,
        sanitizationCount: next.sanitizationCount,
        signalCount: next.signalCount,
        firstSignalAt: prev?.firstSignalAt || bucket.firstTs,
        lastSignalAt: bucket.lastTs,
        lastEventId: bucket.sampleEventIds.at(-1) || prev?.lastEventId || null,
        lastSpanId: bucket.sampleSpanIds.at(-1) || prev?.lastSpanId || null,
        lastBreachLevel: isEscalation ? nextBreach || null : prev?.lastBreachLevel || nextBreach || null,
      },
    });

    if (!nextBreach || !isEscalation) continue;

    const topTool = pickTop(bucket.tools);
    const topDomain = pickTop(bucket.domains);
    const sourceTypes = [...bucket.sourceAlertTypes.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([k]) => k);

    const rollup = {
      category: bucket.category,
      breachLevel: nextBreach,
      signalCount: next.signalCount,
      blockCount: next.blockCount,
      warnCount: next.warnCount,
      modifyCount: next.modifyCount,
      errorCount: next.errorCount,
      sanitizationCount: next.sanitizationCount,
      maxDriftScore: next.driftScore,
      maxRiskScore: bucket.maxRisk,
      firstSignalAt: (prev?.firstSignalAt || bucket.firstTs).toISOString(),
      lastSignalAt: bucket.lastTs.toISOString(),
      topTool,
      topDomain,
      sampleEventIds: bucket.sampleEventIds,
      sampleSpanIds: bucket.sampleSpanIds,
      sourceAlertTypes: sourceTypes,
      previousBreachLevel: prevBreach || null,
      breachTransition: prevBreach ? `${prevBreach}->${nextBreach}` : `none->${nextBreach}`,
    } as Prisma.InputJsonValue;

    const incidentKey = `exec:${bucket.executionId}:${bucket.category}:${nextBreach}`;
    const ruleName = categoryRuleName(bucket.category);
    const eventOutcome = deriveEventOutcome(bucket, nextBreach);
    alerts.push({
      alertKey: incidentKey,
      dedupeKey: incidentKey,
      ts: bucket.lastTs,
      ruleId: `execution.${bucket.category}.${nextBreach}`,
      ruleName,
      ruleSeverity: severityFromBreach(nextBreach),
      ruleCategory: "execution",
      ruleDescription: deriveRuleDescription(bucket),
      eventCategory: "execution",
      eventAction: `risk.${bucket.category}`,
      eventId: bucket.sampleEventIds[0] || null,
      eventOutcome,
      requestId: bucket.requestId,
      projectId: bucket.projectId,
      agentInstanceId: bucket.agentInstanceId,
      openclawAgentId: bucket.openclawAgentId,
      openclawSessionKey: bucket.openclawSessionKey,
      riskScore: Math.max(bucket.maxRisk, nextBreach === "critical" ? 95 : nextBreach === "high" ? 80 : 50),
      status: "open",
      alertType: categoryAlertType(bucket.category),
      triggerType: bucket.triggerType,
      executionId: bucket.executionId,
      rootExecutionId: bucket.rootExecutionId || bucket.executionId,
      topTool,
      topDomain,
      driftScore: next.driftScore,
      alertModel: "execution_v2",
      executionCategory: bucket.category,
      breachLevel: nextBreach,
      rollup,
      details: {
        executionId: bucket.executionId,
        rootExecutionId: bucket.rootExecutionId || bucket.executionId,
        executionCategory: bucket.category,
        breachLevel: nextBreach,
        breachTransition: prevBreach ? `${prevBreach}->${nextBreach}` : `none->${nextBreach}`,
        topTool,
        topDomain,
        blockCount: next.blockCount,
        warnCount: next.warnCount,
        modifyCount: next.modifyCount,
        errorCount: next.errorCount,
        sanitizationCount: next.sanitizationCount,
        maxDriftScore: next.driftScore,
      } as Prisma.InputJsonValue,
    });
  }

  return alerts;
}
