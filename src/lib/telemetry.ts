/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/telemetry.ts.
 */
import crypto from "node:crypto";
import dns from "node:dns/promises";
import { isIP } from "node:net";
import { Prisma } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { deriveManagedAgentKey } from "@/lib/agents/identity";
import { upsertDiscoveredAgents, type DiscoverAgentInput } from "@/lib/agents/repository";
import {
  buildExecutionRiskAlerts,
  mapExecutionAlertCategory,
  type ExecutionRiskSignal,
} from "@/lib/alerts/execution-risk";
import { defaultSeverityFromRisk, evaluateDetections } from "@/lib/detection";
import { normalizeTelemetryEvent, type NormalizeTelemetryInput } from "@/lib/ingest/normalize";
import {
  resolveTraceSourceType,
  resolveTraceSpanStatus,
  resolveTraceStage,
  resolveTraceStatusFromRollup,
  summarizePayloadForTraceSpan,
  type TraceSourceType,
} from "@/lib/traces/lifecycle";

export type TelemetryCategory =
  | "agent"
  | "message"
  | "tool"
  | "session"
  | "gateway"
  | "diagnostic"
  | "log"
  | "policy"
  | "payment";

export type TelemetryInput = NormalizeTelemetryInput & {
  category: TelemetryCategory | string;
};

type PreparedEvent = {
  row: Prisma.TelemetryEventCreateManyInput;
  observables: Array<{
    kind: string;
    value: string;
    valueHash: string;
    confidence?: number;
  }>;
  detection: ReturnType<typeof evaluateDetections>;
  eventId: string;
};

type DomainIpAggregate = {
  domain: string;
  domainHash: string;
  ip: string;
  ipHash: string;
  source: string;
  hits: number;
  firstSeenAt: Date;
  lastSeenAt: Date;
};

type TraceSeed = {
  traceId: string;
  sourceType: TraceSourceType;
  startedAt: Date;
  lastEventTs: Date;
  firstCategory: string;
  firstAction: string;
  projectId: string | null;
  agentInstanceId: string | null;
  requestId: string | null;
  rootExecutionId: string | null;
  rootMessageId: string | null;
  openclawAgentId: string | null;
  openclawSessionKey: string | null;
  openclawSessionId: string | null;
  openclawRunId: string | null;
};

type TraceSpanInsert = {
  traceId: string;
  spanId: string;
  parentSpanId: string | null;
  eventExternalId: string;
  ts: Date;
  stage: string;
  sourceType: TraceSourceType;
  status: string;
  category: string;
  action: string;
  severity: string;
  outcome: string | null;
  outcomeReason: string | null;
  durationMs: number | null;
  latencyMs: number | null;
  errorClass: string | null;
  errorCode: string | null;
  toolName: string | null;
  requestId: string | null;
  rootExecutionId: string | null;
  rootMessageId: string | null;
  sessionKey: string | null;
  sessionId: string | null;
  runId: string | null;
  openclawAgentId: string | null;
  riskScore: number | null;
  payloadSummary: Prisma.InputJsonValue | null;
};

const MULTI_LABEL_PUBLIC_SUFFIXES = new Set([
  "co.uk",
  "org.uk",
  "ac.uk",
  "gov.uk",
  "co.jp",
  "com.au",
  "net.au",
  "org.au",
  "co.nz",
  "com.br",
  "com.mx",
]);

function normalizeDnsEnrichmentMode(value: string): "apex" | "full" {
  const normalized = String(value || "").trim().toLowerCase();
  return normalized === "full" ? "full" : "apex";
}

const DNS_ENRICHMENT_MODE = normalizeDnsEnrichmentMode(
  process.env.SIEM_DNS_ENRICHMENT_MODE || process.env.CLAWSIGHT_DNS_ENRICHMENT_MODE || "apex",
);

function normalizeKey(value: unknown): string | null {
  const raw = typeof value === "string" ? value.trim() : "";
  return raw.length > 0 ? raw : null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

/**
 * Derives durable agent-discovery signals from prepared telemetry rows.
 *
 * Signals are merged by canonical managed-agent key to avoid duplicate upserts while still
 * preserving latest-seen timestamps and bootstrap metadata.
 */
function buildAgentDiscoverySignals(prepared: PreparedEvent[]): DiscoverAgentInput[] {
  const merged = new Map<string, DiscoverAgentInput>();

  for (const item of prepared) {
    const row = item.row;
    const projectId = normalizeKey(row.projectId);
    const agentInstanceId = normalizeKey(row.agentInstanceId);
    const openclawAgentId = normalizeKey(row.openclawAgentId);
    const openclawSessionId = normalizeKey(row.openclawSessionId);
    const openclawSessionKey = normalizeKey(row.openclawSessionKey);
    const agentName = normalizeKey(row.agentName);
    if (!agentInstanceId && !openclawAgentId && !openclawSessionId && !openclawSessionKey) {
      continue;
    }

    const payloadRec = asRecord(row.payload) || asRecord(row.payloadRedacted);
    const profile =
      asRecord(payloadRec?.agentProfile) ||
      asRecord(payloadRec?.agent) ||
      null;
    const runtimeMeta = profile ? (profile as Prisma.InputJsonValue) : null;
    const reportedName =
      agentName ||
      normalizeKey(profile?.agentName) ||
      normalizeKey(profile?.name) ||
      null;
    const isBootstrap = String(row.category || "").toLowerCase() === "agent" && String(row.action || "").toLowerCase() === "bootstrap";

    const next: DiscoverAgentInput = {
      projectId,
      agentInstanceId,
      agentName: reportedName,
      openclawAgentId,
      openclawSessionId,
      openclawSessionKey,
      seenAt: row.ts instanceof Date ? row.ts : new Date(row.ts),
      sourceType: isBootstrap ? "bootstrap" : "discovered",
      reportedName,
      runtimeMeta,
      bootstrapAt: isBootstrap ? (row.ts instanceof Date ? row.ts : new Date(row.ts)) : null,
    };

    const key = deriveManagedAgentKey(next);
    const prev = merged.get(key);
    if (!prev) {
      merged.set(key, next);
      continue;
    }

    const latestSeen = next.seenAt > prev.seenAt ? next.seenAt : prev.seenAt;
    const preferBootstrap = next.sourceType === "bootstrap" || prev.sourceType === "bootstrap";
    const mergedItem: DiscoverAgentInput = {
      projectId: next.projectId || prev.projectId,
      agentInstanceId: next.agentInstanceId || prev.agentInstanceId,
      agentName: next.agentName || prev.agentName,
      openclawAgentId: next.openclawAgentId || prev.openclawAgentId,
      openclawSessionId: next.openclawSessionId || prev.openclawSessionId,
      openclawSessionKey: next.openclawSessionKey || prev.openclawSessionKey,
      seenAt: latestSeen,
      sourceType: preferBootstrap ? "bootstrap" : "discovered",
      reportedName: next.reportedName || prev.reportedName,
      runtimeMeta: next.runtimeMeta || prev.runtimeMeta,
      bootstrapAt: next.bootstrapAt || prev.bootstrapAt || null,
    };
    merged.set(key, mergedItem);
  }

  return [...merged.values()];
}

function resolveStrongExecutionKey(row: Prisma.TelemetryEventCreateManyInput): string | null {
  return (
    normalizeKey(row.rootExecutionId) ||
    normalizeKey(row.traceId) ||
    normalizeKey(row.rootMessageId) ||
    normalizeKey(row.openclawRunId) ||
    null
  );
}

function resolveWeakExecutionKey(row: Prisma.TelemetryEventCreateManyInput): string | null {
  return normalizeKey(row.traceId) || null;
}

function genericBlockMatch(event: PreparedEvent) {
  return {
    ruleId: "policy.blocked-action",
    ruleName: "Policy blocked action",
    severity: defaultSeverityFromRisk(event.row.riskScore ?? 70),
    category: "policy",
    description: "Event outcome is blocked",
    details: {
      reason: event.row.outcomeReason ?? "policy block",
      category: event.row.category,
      action: event.row.action,
    },
  };
}

function mapTraceSourceTypeToTriggerType(sourceType: TraceSourceType): string {
  switch (sourceType) {
    case "user":
      return "user";
    case "cron":
      return "cron";
    case "hook":
    case "webhook":
      return "webhook";
    case "queue":
      return "retry";
    case "heartbeat":
    case "system":
      return "system";
    default:
      return "system";
  }
}

function deriveAlertType(input: {
  ruleId: string;
  ruleCategory?: string | null;
  eventCategory?: string | null;
  eventOutcome?: string | null;
  eventAction?: string | null;
  traceSpanStatus?: string | null;
}): string {
  const ruleId = String(input.ruleId || "").trim().toLowerCase();
  const ruleCategory = String(input.ruleCategory || "").trim().toLowerCase();
  const eventCategory = String(input.eventCategory || "").trim().toLowerCase();
  const eventOutcome = String(input.eventOutcome || "").trim().toLowerCase();
  const eventAction = String(input.eventAction || "").trim().toLowerCase();
  const traceSpanStatus = String(input.traceSpanStatus || "").trim().toLowerCase();

  if (ruleId.includes("intent") || eventAction.includes("intent") || ruleCategory.includes("intent")) {
    return "intent_drift";
  }
  if (
    ruleId.includes("prompt") ||
    ruleId.includes("injection") ||
    ruleCategory.includes("prompt") ||
    ruleCategory.includes("injection")
  ) {
    return "tool_output_injection";
  }
  if (eventCategory === "policy" && (eventOutcome === "block" || traceSpanStatus === "block")) {
    return "policy_block";
  }
  if (
    eventOutcome === "error" ||
    traceSpanStatus === "error" ||
    ruleId.includes("runtime.error") ||
    ruleId.includes("run-failure")
  ) {
    return "execution_error";
  }
  if (eventCategory === "policy") {
    return "policy_decision";
  }
  return "execution_anomaly";
}

function numberFromUnknown(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return Math.round(value);
  if (typeof value === "string") {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return Math.round(parsed);
  }
  return null;
}

function extractDriftScore(payload: unknown): number | null {
  const rec = asRecord(payload);
  if (!rec) return null;

  const directKeys = ["driftScore", "intentDriftScore", "cumulativeDriftScore", "score"];
  for (const key of directKeys) {
    const value = numberFromUnknown(rec[key]);
    if (value != null) return value;
  }

  const nestedKeys = ["intent", "policy", "decision", "signals", "meta"];
  for (const key of nestedKeys) {
    const nested = asRecord(rec[key]);
    if (!nested) continue;
    const nestedDirectKeys = ["driftScore", "intentDriftScore", "cumulativeDriftScore", "score"];
    for (const nestedKey of nestedDirectKeys) {
      const value = numberFromUnknown(nested[nestedKey]);
      if (value != null) return value;
    }
  }

  return null;
}

function hashLower(value: string): string {
  return crypto.createHash("sha256").update(value.toLowerCase(), "utf8").digest("hex");
}

function toSafeNumber(value: bigint | number | null | undefined): number {
  if (typeof value === "number") return value;
  if (typeof value === "bigint") return Number(value);
  return 0;
}

function normalizeDomain(value: string): string {
  return value.trim().toLowerCase().replace(/\.$/, "");
}

function toRegistrableDomain(domain: string): string {
  const labels = domain.split(".").filter(Boolean);
  if (labels.length <= 2) return domain;
  const lastTwo = labels.slice(-2).join(".");
  if (MULTI_LABEL_PUBLIC_SUFFIXES.has(lastTwo) && labels.length >= 3) {
    return labels.slice(-3).join(".");
  }
  return lastTwo;
}

function toDnsLookupDomain(domain: string): string {
  const normalized = normalizeDomain(domain);
  if (!normalized) return "";
  if (DNS_ENRICHMENT_MODE === "full") return normalized;
  return toRegistrableDomain(normalized);
}

function isMissingDomainIpTableError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  const message = err.message.toLowerCase();
  return message.includes("domainipresolution") && message.includes("does not exist");
}

function isMissingTraceTableError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  const message = err.message.toLowerCase();
  return (
    message.includes("does not exist") &&
    (message.includes("trace\"") || message.includes("tracespan\"") || message.includes("trace "))
  );
}

function isMissingTraceOrphanTableError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  const message = err.message.toLowerCase();
  return message.includes("does not exist") && message.includes("traceorphan");
}

function shouldResolveDomainsForEvent(item: PreparedEvent): boolean {
  const category = String(item.row.category || "").trim().toLowerCase();
  const action = String(item.row.action || "").trim().toLowerCase();
  const outcome = String(item.row.outcome || item.row.result || "").trim().toLowerCase();
  if (outcome === "block" || outcome === "error") return false;
  if (category === "tool" || category === "payment") return true;
  if (category === "agent" || category === "gateway" || category === "diagnostic") return false;
  return (
    action.includes("web") ||
    action.includes("fetch") ||
    action.includes("navigate") ||
    action.includes("http") ||
    action.includes("url") ||
    action.includes("request")
  );
}

async function lookupDomainWithTimeout(domain: string, timeoutMs: number): Promise<Array<{ address: string }>> {
  let timer: ReturnType<typeof setTimeout> | null = null;
  try {
    const records = (await Promise.race([
      dns.lookup(domain, { all: true, verbatim: true }),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("dns_lookup_timeout")), timeoutMs);
      }),
    ])) as Array<{ address: string }>;
    return records;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function resolveDomainIps(domains: string[]): Promise<Map<string, string[]>> {
  const out = new Map<string, string[]>();
  const uniqueDomains = [...new Set(domains.map((domain) => normalizeDomain(domain)).filter(Boolean))]
    .filter((domain) => isIP(domain) === 0)
    .slice(0, 40);
  const lookupByDomain = new Map<string, string>();
  const uniqueLookupDomains = new Set<string>();
  for (const domain of uniqueDomains) {
    const lookupDomain = toDnsLookupDomain(domain);
    if (!lookupDomain) continue;
    lookupByDomain.set(domain, lookupDomain);
    uniqueLookupDomains.add(lookupDomain);
  }
  const resolvedByLookupDomain = new Map<string, string[]>();

  await Promise.all(
    [...uniqueLookupDomains].map(async (domain) => {
      try {
        const records = await lookupDomainWithTimeout(domain, 700);
        const ips = [...new Set(records.map((record) => record.address.trim()).filter((ip) => isIP(ip) !== 0))].slice(0, 8);
        resolvedByLookupDomain.set(domain, ips);
      } catch {
        resolvedByLookupDomain.set(domain, []);
      }
    }),
  );

  for (const [domain, lookupDomain] of lookupByDomain.entries()) {
    out.set(domain, resolvedByLookupDomain.get(lookupDomain) || []);
  }

  return out;
}

/**
 * Ingests normalized telemetry envelopes and materializes all downstream state.
 *
 * Pipeline stages:
 * - deduplicate by `eventId`
 * - normalize + detect risk signals
 * - persist events/observables
 * - build execution-level alerts and domain/IP resolutions
 * - update traces/spans + orphan tracking
 * - upsert managed-agent discovery records
 *
 * @param events Raw telemetry envelopes from plugin/gateway ingestion.
 * @returns Insert counts for all derived artifacts.
 */
export async function ingestEvents(events: TelemetryInput[]) {
  if (!Array.isArray(events) || events.length === 0) {
    return { count: 0, inserted: 0, alerts: 0, observables: 0 };
  }

  const inputEventIds = [...new Set(events.map((evt) => normalizeKey((evt as { eventId?: unknown }).eventId)).filter(Boolean) as string[])];
  const existingEventIds = new Set<string>();
  if (inputEventIds.length > 0) {
    const existing = await prisma.telemetryEvent.findMany({
      where: { eventId: { in: inputEventIds } },
      select: { eventId: true },
    });
    for (const row of existing) existingEventIds.add(row.eventId);
  }

  const eventsToProcess = existingEventIds.size
    ? events.filter((evt) => {
        const eventId = normalizeKey((evt as { eventId?: unknown }).eventId);
        return !eventId || !existingEventIds.has(eventId);
      })
    : events;
  const duplicatesSkipped = Math.max(0, events.length - eventsToProcess.length);

  if (eventsToProcess.length === 0) {
    return {
      count: events.length,
      inserted: 0,
      alerts: 0,
      observables: 0,
      resolutions: 0,
      orphans: 0,
      traces: 0,
      spans: 0,
      agents: 0,
      duplicatesSkipped,
    };
  }

  const prepared: PreparedEvent[] = eventsToProcess.map((input) => {
    const normalized = normalizeTelemetryEvent(input);
    const detection = evaluateDetections({
      eventId: normalized.row.eventId,
      ts: normalized.row.ts instanceof Date ? normalized.row.ts : new Date(normalized.row.ts),
      severity: normalized.row.severity ?? "info",
      category: normalized.row.category ?? "diagnostic",
      action: normalized.row.action ?? "event",
      result: normalized.row.result,
      outcome: normalized.row.outcome,
      outcomeReason: normalized.row.outcomeReason,
      projectId: normalized.row.projectId,
      agentInstanceId: normalized.row.agentInstanceId,
      requestId: normalized.row.requestId,
      openclaw: {
        agentId: normalized.row.openclawAgentId,
        sessionKey: normalized.row.openclawSessionKey,
      },
      sourceIp: normalized.row.sourceIp,
      durationMs: normalized.row.durationMs,
      payload: normalized.detectionPayload,
    });

    normalized.row.riskScore = detection.riskScore;
    normalized.row.iocType = detection.iocType || null;
    normalized.row.iocValue = detection.iocValue || null;

    return {
      row: normalized.row,
      observables: normalized.observables,
      detection,
      eventId: normalized.row.eventId,
    };
  });

  const preparedFiltered = prepared.filter((item) => {
    if (item.row.category !== "policy") return true;
    const normalizedOutcome = String(item.row.outcome || item.row.result || "").trim().toLowerCase();
    const isDefaultAllow =
      normalizedOutcome === "allow" ||
      normalizedOutcome === "ok" ||
      normalizedOutcome === "success" ||
      normalizedOutcome === "submitted";
    if (!isDefaultAllow) return true;
    return Boolean(item.row.policyRuleId || item.row.policyDecisionId);
  });

  const policyBlockedRequestIds = new Set(
    preparedFiltered
      .filter(
        (item) =>
          item.row.category === "policy" &&
          String(item.row.outcome || "").trim().toLowerCase() === "block" &&
          Boolean(item.row.requestId),
      )
      .map((item) => String(item.row.requestId)),
  );

  if (preparedFiltered.length === 0) {
    return {
      count: events.length,
      inserted: 0,
      alerts: 0,
      observables: 0,
      resolutions: 0,
      orphans: 0,
      traces: 0,
      spans: 0,
      agents: 0,
      duplicatesSkipped,
    };
  }

  const agentSignals = buildAgentDiscoverySignals(preparedFiltered);

  const eventDomainMap = new Map<string, string[]>();
  const allDomains = new Set<string>();
  for (const item of preparedFiltered) {
    if (!shouldResolveDomainsForEvent(item)) continue;
    const domains = [
      ...new Set(
        item.observables
          .filter((observable) => observable.kind === "domain")
          .map((observable) => normalizeDomain(observable.value))
          .filter(Boolean),
      ),
    ];
    if (domains.length === 0) continue;
    eventDomainMap.set(item.eventId, domains);
    for (const domain of domains) {
      allDomains.add(domain);
    }
  }

  const domainIpMap = await resolveDomainIps([...allDomains]);

  const eventRows = preparedFiltered.map((item) => item.row);
  const eventIds = preparedFiltered.map((item) => item.eventId);

  const riskSignals: ExecutionRiskSignal[] = preparedFiltered.flatMap((item) => {
    const baselineMatches = item.detection.matches.length
      ? item.detection.matches
      : item.row.outcome === "block"
        ? [genericBlockMatch(item)]
        : [];

    const shouldSuppressToolErrorAlerts =
      item.row.category === "tool" &&
      String(item.row.outcome || "").trim().toLowerCase() === "error" &&
      Boolean(item.row.requestId) &&
      policyBlockedRequestIds.has(String(item.row.requestId));

    const matches = shouldSuppressToolErrorAlerts
      ? baselineMatches.filter(
          (match) => match.ruleId !== "runtime.error" && match.ruleId !== "tool.exec.suspicious-pattern",
        )
      : baselineMatches;

    const traceSourceType = resolveTraceSourceType({
      category: item.row.category,
      action: item.row.action,
      sessionKey: item.row.openclawSessionKey,
      payload: item.row.payload ?? item.row.payloadRedacted,
    });
    const traceSpanStatus = resolveTraceSpanStatus({
      category: item.row.category,
      action: item.row.action,
      outcome: item.row.outcome,
      severity: item.row.severity,
      errorClass: item.row.errorClass,
      errorCode: item.row.errorCode,
    });

    return matches
      .map((match) => {
        const executionId =
          resolveStrongExecutionKey(item.row) ||
          normalizeKey(item.row.requestId) ||
          normalizeKey(item.row.openclawSessionKey);
        if (!executionId) return null;

        const payload = item.row.payload ?? item.row.payloadRedacted;
        const payloadRec = asRecord(payload);
        const triggerType = mapTraceSourceTypeToTriggerType(traceSourceType);
        const topTool =
          normalizeKey(item.row.openclawToolName) ||
          normalizeKey(payloadRec?.toolName) ||
          null;
        const topDomain = eventDomainMap.get(item.eventId)?.[0] || null;
        const driftScore = extractDriftScore(payload);
        const alertType = deriveAlertType({
          ruleId: match.ruleId,
          ruleCategory: match.category,
          eventCategory: item.row.category,
          eventOutcome: item.row.outcome,
          eventAction: item.row.action,
          traceSpanStatus,
        });
        const category = mapExecutionAlertCategory({
          alertType,
          eventCategory: item.row.category,
          eventOutcome: item.row.outcome,
          ruleCategory: match.category,
          ruleId: match.ruleId,
        });

        const riskScore = item.row.riskScore ?? item.detection.riskScore;
        return {
          ts: item.row.ts instanceof Date ? item.row.ts : new Date(item.row.ts),
          eventId: item.eventId,
          spanId: item.row.spanId ?? null,
          executionId,
          rootExecutionId: item.row.rootExecutionId || executionId,
          projectId: item.row.projectId ?? null,
          agentInstanceId: item.row.agentInstanceId ?? null,
          openclawAgentId: item.row.openclawAgentId ?? null,
          openclawSessionKey: item.row.openclawSessionKey ?? null,
          requestId: item.row.requestId ?? null,
          triggerType,
          category,
          alertType,
          ruleId: match.ruleId,
          ruleName: match.ruleName,
          ruleCategory: match.category,
          ruleDescription: match.description ?? null,
          ruleSeverity: defaultSeverityFromRisk(riskScore),
          eventCategory: item.row.category ?? null,
          eventAction: item.row.action ?? null,
          eventOutcome: item.row.outcome ?? null,
          outcomeReason: item.row.outcomeReason ?? null,
          riskScore,
          driftScore,
          toolName: topTool,
          domain: topDomain,
        } satisfies ExecutionRiskSignal;
      })
      .filter(Boolean) as ExecutionRiskSignal[];
  });

  const result = await prisma.$transaction(async (tx) => {
    const insertedEvents = await tx.telemetryEvent.createMany({
      data: eventRows,
      skipDuplicates: true,
    });

    const persistedEvents = await tx.telemetryEvent.findMany({
      where: {
        eventId: { in: eventIds },
      },
      select: {
        id: true,
        eventId: true,
        ts: true,
      },
    });

    const eventMap = new Map<string, { id: number; ts: Date }>();
    for (const row of persistedEvents) {
      eventMap.set(row.eventId, { id: row.id, ts: row.ts });
    }

    const observablesData: Prisma.TelemetryObservableCreateManyInput[] = [];
    const domainIpAggregates = new Map<string, DomainIpAggregate>();

    const trackDomainIp = (domain: string, ip: string, seenAt: Date) => {
      const normalizedDomain = normalizeDomain(domain);
      const normalizedIp = ip.trim();
      if (!normalizedDomain || !normalizedIp || isIP(normalizedIp) === 0) return;
      const key = `${normalizedDomain}|${normalizedIp}|dns`;
      const existing = domainIpAggregates.get(key);
      if (existing) {
        existing.hits += 1;
        if (seenAt < existing.firstSeenAt) existing.firstSeenAt = seenAt;
        if (seenAt > existing.lastSeenAt) existing.lastSeenAt = seenAt;
        return;
      }
      domainIpAggregates.set(key, {
        domain: normalizedDomain,
        domainHash: hashLower(normalizedDomain),
        ip: normalizedIp,
        ipHash: hashLower(normalizedIp),
        source: "dns",
        hits: 1,
        firstSeenAt: seenAt,
        lastSeenAt: seenAt,
      });
    };

    for (const item of preparedFiltered) {
      const persisted = eventMap.get(item.eventId);
      if (!persisted) continue;
      for (const observable of item.observables) {
        observablesData.push({
          eventId: persisted.id,
          eventTs: persisted.ts,
          kind: observable.kind,
          value: observable.value,
          valueHash: observable.valueHash,
          confidence: observable.confidence ?? null,
        });
      }
      if (item.row.iocType && item.row.iocValue) {
        observablesData.push({
          eventId: persisted.id,
          eventTs: persisted.ts,
          kind: item.row.iocType,
          value: item.row.iocValue,
          valueHash: item.row.iocValue ? item.row.iocValue.toLowerCase() : "",
          confidence: 95,
        });
      }

      const eventDomains = eventDomainMap.get(item.eventId) ?? [];
      for (const domain of eventDomains) {
        const resolvedIps = domainIpMap.get(domain) ?? [];
        for (const ip of resolvedIps) {
          observablesData.push({
            eventId: persisted.id,
            eventTs: persisted.ts,
            kind: "ip",
            value: ip,
            valueHash: hashLower(ip),
            confidence: 60,
          });
          trackDomainIp(domain, ip, persisted.ts);
        }
      }
    }

    const observablesInserted = observablesData.length
      ? await tx.telemetryObservable.createMany({
          data: observablesData.map((item) => ({
            ...item,
            valueHash: item.valueHash || item.value.toLowerCase(),
          })),
          skipDuplicates: true,
        })
      : { count: 0 };

    const incidentAlerts = await buildExecutionRiskAlerts(tx, riskSignals);

    const alertsInserted = incidentAlerts.length
      ? await tx.threatAlert.createMany({
          data: incidentAlerts,
          skipDuplicates: true,
        })
      : { count: 0 };

    let insertedOrphans = 0;
    try {
      const orphanRows: Prisma.TraceOrphanCreateManyInput[] = [];
      for (const item of preparedFiltered) {
        const persisted = eventMap.get(item.eventId);
        if (!persisted) continue;

        const payload =
          (item.row.payload as Prisma.InputJsonValue | null) ??
          (item.row.payloadRedacted as Prisma.InputJsonValue | null) ??
          Prisma.JsonNull;
        const payloadRec =
          payload && typeof payload === "object" && !Array.isArray(payload)
            ? (payload as Record<string, unknown>)
            : null;

        const flaggedOrphan = payloadRec?.__traceOrphan === true;
        const missingTraceId = !String(item.row.traceId || "").trim();
        if (!flaggedOrphan && !missingTraceId) continue;

        const reasonFromPayload =
          typeof payloadRec?.__traceOrphanReason === "string"
            ? String(payloadRec.__traceOrphanReason).trim()
            : "";
        const reason = reasonFromPayload || (missingTraceId ? "missing_trace_id" : "trace_orphan");
        const traceHint =
          String(item.row.traceId || "").trim() ||
          String(item.row.rootExecutionId || "").trim() ||
          String(item.row.correlationId || "").trim() ||
          String(item.row.requestId || "").trim() ||
          null;

        orphanRows.push({
          eventExternalId: item.eventId,
          eventTs: persisted.ts,
          eventCategory: item.row.category ?? null,
          eventAction: item.row.action ?? null,
          reason,
          traceHint,
          requestId: item.row.requestId ?? null,
          rootExecutionId: item.row.rootExecutionId ?? null,
          rootMessageId: item.row.rootMessageId ?? null,
          openclawSessionKey: item.row.openclawSessionKey ?? null,
          payload,
        });
      }
      if (orphanRows.length > 0) {
        const inserted = await tx.traceOrphan.createMany({ data: orphanRows });
        insertedOrphans = inserted.count;
      }
    } catch (err) {
      if (!isMissingTraceOrphanTableError(err)) {
        throw err;
      }
    }

    let insertedResolutions = 0;
    if (domainIpAggregates.size > 0) {
      try {
        for (const row of domainIpAggregates.values()) {
          await tx.$executeRaw`
            INSERT INTO "DomainIpResolution"
              ("domain", "domainHash", "ip", "ipHash", "source", "hits", "firstSeenAt", "lastSeenAt", "createdAt", "updatedAt")
            VALUES
              (${row.domain}, ${row.domainHash}, ${row.ip}, ${row.ipHash}, ${row.source}, ${row.hits}, ${row.firstSeenAt}, ${row.lastSeenAt}, NOW(), NOW())
            ON CONFLICT ("domainHash", "ipHash", "source")
            DO UPDATE SET
              "domain" = EXCLUDED."domain",
              "ip" = EXCLUDED."ip",
              "hits" = "DomainIpResolution"."hits" + EXCLUDED."hits",
              "firstSeenAt" = LEAST("DomainIpResolution"."firstSeenAt", EXCLUDED."firstSeenAt"),
              "lastSeenAt" = GREATEST("DomainIpResolution"."lastSeenAt", EXCLUDED."lastSeenAt"),
              "updatedAt" = NOW()
          `;
          insertedResolutions += row.hits;
        }
      } catch (err) {
        if (!isMissingDomainIpTableError(err)) {
          throw err;
        }
      }
    }

    let insertedTraces = 0;
    let insertedSpans = 0;
    try {
      const traceSeeds = new Map<string, TraceSeed>();
      const traceSpans: TraceSpanInsert[] = [];
      const requestExecutionKey = new Map<string, string>();

      for (const item of preparedFiltered) {
        const requestId = normalizeKey(item.row.requestId);
        if (!requestId) continue;
        const strongExecutionKey = resolveStrongExecutionKey(item.row);
        if (!strongExecutionKey) continue;
        if (!requestExecutionKey.has(requestId)) {
          requestExecutionKey.set(requestId, strongExecutionKey);
        }
      }

      for (const item of preparedFiltered) {
        const persisted = eventMap.get(item.eventId);
        if (!persisted) continue;

        const traceId =
          resolveStrongExecutionKey(item.row) ||
          (normalizeKey(item.row.requestId) ? requestExecutionKey.get(normalizeKey(item.row.requestId) as string) ?? null : null) ||
          resolveWeakExecutionKey(item.row);
        if (!traceId) continue;

        const spanId = String(item.row.spanId || item.row.eventId || item.eventId).trim() || item.eventId;
        const parentSpanId =
          String(item.row.parentSpanId || "").trim() ||
          (item.row.payload &&
          typeof item.row.payload === "object" &&
          !Array.isArray(item.row.payload) &&
          typeof (item.row.payload as Record<string, unknown>).parentSpanId === "string"
            ? ((item.row.payload as Record<string, unknown>).parentSpanId as string)
            : null);

        const sourceType = resolveTraceSourceType({
          category: item.row.category,
          action: item.row.action,
          sessionKey: item.row.openclawSessionKey,
          payload: item.row.payload ?? item.row.payloadRedacted,
        });
        const stage = resolveTraceStage({
          category: item.row.category,
          action: item.row.action,
          outcome: item.row.outcome,
          payload: item.row.payload ?? item.row.payloadRedacted,
        });
        const status = resolveTraceSpanStatus({
          category: item.row.category,
          action: item.row.action,
          outcome: item.row.outcome,
          severity: item.row.severity,
          errorClass: item.row.errorClass,
          errorCode: item.row.errorCode,
        });

        traceSpans.push({
          traceId,
          spanId,
          parentSpanId,
          eventExternalId: item.eventId,
          ts: persisted.ts,
          stage,
          sourceType,
          status,
          category: item.row.category || "diagnostic",
          action: item.row.action || "event",
          severity: item.row.severity || "info",
          outcome: item.row.outcome || null,
          outcomeReason: item.row.outcomeReason || null,
          durationMs: item.row.durationMs ?? null,
          latencyMs: item.row.latencyMs ?? null,
          errorClass: item.row.errorClass ?? null,
          errorCode: item.row.errorCode ?? null,
          toolName: item.row.openclawToolName ?? null,
          requestId: item.row.requestId ?? null,
          rootExecutionId: item.row.rootExecutionId ?? null,
          rootMessageId: item.row.rootMessageId ?? null,
          sessionKey: item.row.openclawSessionKey ?? null,
          sessionId: item.row.openclawSessionId ?? null,
          runId: item.row.openclawRunId ?? null,
          openclawAgentId: item.row.openclawAgentId ?? null,
          riskScore: item.row.riskScore ?? null,
          payloadSummary: summarizePayloadForTraceSpan(item.row.payload ?? item.row.payloadRedacted) as Prisma.InputJsonValue | null,
        });

        const currentSeed = traceSeeds.get(traceId);
        if (!currentSeed) {
          traceSeeds.set(traceId, {
            traceId,
            sourceType,
            startedAt: persisted.ts,
            lastEventTs: persisted.ts,
            firstCategory: item.row.category || "diagnostic",
            firstAction: item.row.action || "event",
            projectId: item.row.projectId ?? null,
            agentInstanceId: item.row.agentInstanceId ?? null,
            requestId: item.row.requestId ?? null,
            rootExecutionId: item.row.rootExecutionId ?? null,
            rootMessageId: item.row.rootMessageId ?? null,
            openclawAgentId: item.row.openclawAgentId ?? null,
            openclawSessionKey: item.row.openclawSessionKey ?? null,
            openclawSessionId: item.row.openclawSessionId ?? null,
            openclawRunId: item.row.openclawRunId ?? null,
          });
        } else {
          if (persisted.ts < currentSeed.startedAt) currentSeed.startedAt = persisted.ts;
          if (persisted.ts > currentSeed.lastEventTs) currentSeed.lastEventTs = persisted.ts;
          if (currentSeed.sourceType === "user" && sourceType !== "user") {
            currentSeed.sourceType = sourceType;
          }
          if (!currentSeed.projectId && item.row.projectId) currentSeed.projectId = item.row.projectId;
          if (!currentSeed.agentInstanceId && item.row.agentInstanceId) currentSeed.agentInstanceId = item.row.agentInstanceId;
          if (!currentSeed.requestId && item.row.requestId) currentSeed.requestId = item.row.requestId;
          if (!currentSeed.rootExecutionId && item.row.rootExecutionId) currentSeed.rootExecutionId = item.row.rootExecutionId;
          if (!currentSeed.rootMessageId && item.row.rootMessageId) currentSeed.rootMessageId = item.row.rootMessageId;
          if (!currentSeed.openclawAgentId && item.row.openclawAgentId) currentSeed.openclawAgentId = item.row.openclawAgentId;
          if (!currentSeed.openclawSessionKey && item.row.openclawSessionKey) currentSeed.openclawSessionKey = item.row.openclawSessionKey;
          if (!currentSeed.openclawSessionId && item.row.openclawSessionId) currentSeed.openclawSessionId = item.row.openclawSessionId;
          if (!currentSeed.openclawRunId && item.row.openclawRunId) currentSeed.openclawRunId = item.row.openclawRunId;
        }
      }

      if (traceSeeds.size > 0) {
        for (const seed of traceSeeds.values()) {
          await tx.$executeRaw`
            INSERT INTO "Trace"
              ("traceId", "sourceType", "status", "startedAt", "lastEventTs", "firstCategory", "firstAction", "projectId", "agentInstanceId", "requestId", "rootExecutionId", "rootMessageId", "openclawAgentId", "openclawSessionKey", "openclawSessionId", "openclawRunId", "createdAt", "updatedAt")
            VALUES
              (${seed.traceId}, ${seed.sourceType}, 'running', ${seed.startedAt}, ${seed.lastEventTs}, ${seed.firstCategory}, ${seed.firstAction}, ${seed.projectId}, ${seed.agentInstanceId}, ${seed.requestId}, ${seed.rootExecutionId}, ${seed.rootMessageId}, ${seed.openclawAgentId}, ${seed.openclawSessionKey}, ${seed.openclawSessionId}, ${seed.openclawRunId}, NOW(), NOW())
            ON CONFLICT ("traceId")
            DO UPDATE SET
              "lastEventTs" = GREATEST("Trace"."lastEventTs", EXCLUDED."lastEventTs"),
              "startedAt" = LEAST("Trace"."startedAt", EXCLUDED."startedAt"),
              "sourceType" = CASE
                WHEN "Trace"."sourceType" = 'user' AND EXCLUDED."sourceType" <> 'user' THEN EXCLUDED."sourceType"
                ELSE "Trace"."sourceType"
              END,
              "projectId" = COALESCE("Trace"."projectId", EXCLUDED."projectId"),
              "agentInstanceId" = COALESCE("Trace"."agentInstanceId", EXCLUDED."agentInstanceId"),
              "requestId" = COALESCE("Trace"."requestId", EXCLUDED."requestId"),
              "rootExecutionId" = COALESCE("Trace"."rootExecutionId", EXCLUDED."rootExecutionId"),
              "rootMessageId" = COALESCE("Trace"."rootMessageId", EXCLUDED."rootMessageId"),
              "openclawAgentId" = COALESCE("Trace"."openclawAgentId", EXCLUDED."openclawAgentId"),
              "openclawSessionKey" = COALESCE("Trace"."openclawSessionKey", EXCLUDED."openclawSessionKey"),
              "openclawSessionId" = COALESCE("Trace"."openclawSessionId", EXCLUDED."openclawSessionId"),
              "openclawRunId" = COALESCE("Trace"."openclawRunId", EXCLUDED."openclawRunId"),
              "updatedAt" = NOW()
          `;
          insertedTraces += 1;
        }
      }

      if (traceSpans.length > 0) {
        for (const span of traceSpans) {
          const inserted = await tx.$executeRaw`
            INSERT INTO "TraceSpan"
              ("traceId", "spanId", "parentSpanId", "eventExternalId", "ts", "stage", "sourceType", "status", "category", "action", "severity", "outcome", "outcomeReason", "durationMs", "latencyMs", "errorClass", "errorCode", "toolName", "requestId", "rootExecutionId", "rootMessageId", "sessionKey", "sessionId", "runId", "openclawAgentId", "riskScore", "payloadSummary", "createdAt", "updatedAt")
            VALUES
              (${span.traceId}, ${span.spanId}, ${span.parentSpanId}, ${span.eventExternalId}, ${span.ts}, ${span.stage}, ${span.sourceType}, ${span.status}, ${span.category}, ${span.action}, ${span.severity}, ${span.outcome}, ${span.outcomeReason}, ${span.durationMs}, ${span.latencyMs}, ${span.errorClass}, ${span.errorCode}, ${span.toolName}, ${span.requestId}, ${span.rootExecutionId}, ${span.rootMessageId}, ${span.sessionKey}, ${span.sessionId}, ${span.runId}, ${span.openclawAgentId}, ${span.riskScore}, ${span.payloadSummary}, NOW(), NOW())
            ON CONFLICT ("spanId") DO NOTHING
          `;
          insertedSpans += toSafeNumber(inserted);
        }
      }

      const affectedTraceIds = [...traceSeeds.keys()];
      if (affectedTraceIds.length > 0) {
        const rollups = await tx.$queryRaw<Array<{
          traceId: string;
          startedAt: Date;
          lastEventTs: Date;
          spanCount: bigint;
          errorCount: bigint;
          warnCount: bigint;
          blockCount: bigint;
          maxRiskScore: number | null;
          hasRunEnd: boolean;
        }>>`
        SELECT
          "traceId",
          MIN("ts") AS "startedAt",
          MAX("ts") AS "lastEventTs",
          COUNT(*)::bigint AS "spanCount",
          SUM(CASE WHEN "status" = 'error' THEN 1 ELSE 0 END)::bigint AS "errorCount",
          SUM(CASE WHEN "status" = 'warn' THEN 1 ELSE 0 END)::bigint AS "warnCount",
          SUM(CASE WHEN "status" = 'block' THEN 1 ELSE 0 END)::bigint AS "blockCount",
          MAX("riskScore") AS "maxRiskScore",
          BOOL_OR("stage" IN ('run.end', 'llm.output', 'agent.bootstrap')) AS "hasRunEnd"
        FROM "TraceSpan"
        WHERE "traceId" IN (${Prisma.join(affectedTraceIds)})
        GROUP BY "traceId"
        `;

        for (const row of rollups) {
          const errorCount = toSafeNumber(row.errorCount);
          const warnCount = toSafeNumber(row.warnCount);
          const blockCount = toSafeNumber(row.blockCount);
          const spanCount = toSafeNumber(row.spanCount);
          const status = resolveTraceStatusFromRollup({
            errorCount,
            blockCount,
            warnCount,
            hasRunEnd: Boolean(row.hasRunEnd),
          });
          const endedAt = row.hasRunEnd ? row.lastEventTs : null;
          const durationMs = row.hasRunEnd
            ? Math.max(0, row.lastEventTs.getTime() - row.startedAt.getTime())
            : null;

          await tx.$executeRaw`
            UPDATE "Trace"
            SET
              "startedAt" = ${row.startedAt},
              "lastEventTs" = ${row.lastEventTs},
              "endedAt" = ${endedAt},
              "durationMs" = ${durationMs},
              "status" = ${status},
              "spanCount" = ${spanCount},
              "eventCount" = ${spanCount},
              "errorCount" = ${errorCount},
              "warnCount" = ${warnCount},
              "blockCount" = ${blockCount},
              "maxRiskScore" = ${row.maxRiskScore},
              "updatedAt" = NOW()
            WHERE "traceId" = ${row.traceId}
          `;
        }
      }
    } catch (err) {
      if (!isMissingTraceTableError(err)) {
        throw err;
      }
    }

    return {
      insertedEvents: insertedEvents.count,
      insertedAlerts: alertsInserted.count,
      insertedObservables: observablesInserted.count,
      insertedResolutions,
      insertedTraces,
      insertedSpans,
      insertedOrphans,
    };
  });

  let managedAgentsUpserted = 0;
  if (agentSignals.length > 0) {
    try {
      managedAgentsUpserted = await upsertDiscoveredAgents(agentSignals);
    } catch {
      managedAgentsUpserted = 0;
    }
  }

  return {
    count: events.length,
    inserted: result.insertedEvents,
    alerts: result.insertedAlerts,
    observables: result.insertedObservables,
    resolutions: result.insertedResolutions,
    traces: result.insertedTraces,
    spans: result.insertedSpans,
    orphans: result.insertedOrphans,
    agents: managedAgentsUpserted,
    duplicatesSkipped,
  };
}
