/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/executions/mapper.ts.
 */
import { deriveManagedAgentKey } from "@/lib/agents/identity";
import type { Execution, ExecutionIntentSummary, ExecutionOutcome, TriggerType } from "@/lib/executions/types";

export type ExecutionTraceRow = {
  traceId: string;
  sourceType: string;
  status: string;
  startedAt: Date;
  endedAt: Date | null;
  durationMs: number | null;
  errorCount: number;
  blockCount: number;
  openclawSessionKey: string | null;
  openclawAgentId: string | null;
  openclawSessionId: string | null;
  agentInstanceId: string | null;
  projectId: string | null;
  rootExecutionId: string | null;
};

export type ExecutionRollupRow = {
  traceId: string;
  toolCalls: number;
  errors: number;
  domainsTouched: number;
  alertsRaised: number;
  channelsInvolved: string[];
};

function normalize(input: string | null | undefined): string {
  return String(input || "").trim().toLowerCase();
}

function parseCronRef(sessionKey: string): string | undefined {
  const marker = ":cron:";
  const idx = sessionKey.indexOf(marker);
  if (idx < 0) return undefined;
  const tail = sessionKey.slice(idx + marker.length).trim();
  return tail || undefined;
}

function parseHookRef(sessionKey: string): string | undefined {
  const marker = ":hook:";
  const idx = sessionKey.indexOf(marker);
  if (idx < 0) return undefined;
  const tail = sessionKey.slice(idx + marker.length).trim();
  return tail || undefined;
}

function parseMessageExecutionRef(executionId: string): { channel: string; ref?: string } | null {
  const raw = normalize(executionId);
  if (!raw.startsWith("msg:")) return null;
  const parts = raw.split(":").filter(Boolean);
  if (parts.length < 2) return null;
  const channel = parts[1] || "message";
  if (parts.length >= 4 && parts[2] === "conversation") {
    const conversationRef = parts.slice(3).join(":");
    return { channel, ref: conversationRef || undefined };
  }
  const ref = parts.slice(2).join(":");
  return { channel, ref: ref || undefined };
}

function parseSessionChannelRef(sessionKey: string): { channel: string; ref?: string } | null {
  const raw = normalize(sessionKey);
  const parts = raw.split(":").filter(Boolean);
  if (parts.length < 4 || parts[0] !== "agent") return null;
  const channel = parts[2];
  const knownChannels = new Set([
    "webchat",
    "telegram",
    "discord",
    "slack",
    "signal",
    "whatsapp",
    "teams",
    "mattermost",
  ]);
  if (!knownChannels.has(channel)) return null;
  const ref = parts.slice(3).join(":");
  return { channel, ref: ref || undefined };
}

function isDirectMainSession(sessionKey: string): boolean {
  return /^agent:[^:]+:main$/i.test(sessionKey);
}

export function resolveTriggerType(row: ExecutionTraceRow): TriggerType {
  const source = normalize(row.sourceType);
  const sessionKey = normalize(row.openclawSessionKey);

  if (source === "cron" || sessionKey.includes(":cron:")) return "cron";
  if (source === "hook" || source === "webhook" || sessionKey.includes(":hook:")) return "webhook";
  if (source === "retry") return "retry";
  if (source === "chain") return "chain";
  if (source === "system" || source === "heartbeat" || sessionKey.includes(":heartbeat:")) return "system";
  return "user";
}

export function resolveOutcome(row: ExecutionTraceRow): ExecutionOutcome {
  const status = normalize(row.status);

  if (!row.endedAt) {
    if (status === "blocked" || status === "block") return "blocked";
    if (status === "failed" || status === "error" || status === "partial") return "error";
    return "running";
  }

  if (status === "blocked" || status === "block") return "blocked";
  if (status === "failed" || status === "error" || status === "partial") return "error";
  return "completed";
}

export function resolveTriggerInfo(row: ExecutionTraceRow): { source: string; ref?: string } {
  const trigger = resolveTriggerType(row);
  const sessionKey = String(row.openclawSessionKey || "").trim();

  const messageExecution =
    parseMessageExecutionRef(row.rootExecutionId || "") || parseMessageExecutionRef(row.traceId);
  if (trigger === "user" && messageExecution) {
    return { source: messageExecution.channel, ref: messageExecution.ref };
  }

  if (trigger === "cron") {
    const ref = parseCronRef(normalize(sessionKey));
    return { source: ref ? `cron:${ref}` : "cron", ref };
  }
  if (trigger === "webhook") {
    const ref = parseHookRef(normalize(sessionKey));
    return { source: ref ? `hook:${ref}` : "webhook", ref };
  }
  if (trigger === "system") {
    return { source: row.sourceType || "system" };
  }

  const sessionChannel = parseSessionChannelRef(sessionKey);
  if (sessionChannel) {
    return { source: sessionChannel.channel, ref: sessionChannel.ref };
  }

  if (isDirectMainSession(sessionKey)) {
    return { source: "direct-session" };
  }

  const source = row.openclawAgentId || row.agentInstanceId || sessionKey || row.traceId;
  return { source };
}

export function deriveExecutionAgentKey(row: ExecutionTraceRow): string {
  return deriveManagedAgentKey({
    projectId: row.projectId,
    agentInstanceId: row.agentInstanceId,
    openclawAgentId: row.openclawAgentId,
    openclawSessionId: row.openclawSessionId,
    openclawSessionKey: row.openclawSessionKey,
  });
}

export function toExecution(
  row: ExecutionTraceRow,
  rollup: ExecutionRollupRow | undefined,
  agentName: string,
  intentSummary?: ExecutionIntentSummary,
): Execution {
  const triggerType = resolveTriggerType(row);
  const triggerInfo = resolveTriggerInfo(row);
  const outcome = resolveOutcome(row);

  return {
    executionId: row.traceId,
    traceId: row.traceId,
    agentKey: deriveExecutionAgentKey(row),
    agentName,
    triggerType,
    triggerSource: triggerInfo.source,
    triggerRef: triggerInfo.ref,
    outcome,
    startedAt: row.startedAt.toISOString(),
    endedAt: row.endedAt ? row.endedAt.toISOString() : undefined,
    durationMs: row.durationMs ?? undefined,
    rootExecutionId: row.rootExecutionId || undefined,
    parentExecutionId: undefined,
    channelsInvolved: rollup?.channelsInvolved || [],
    intentSummary,
    rollup: {
      toolCalls: rollup?.toolCalls || 0,
      domainsTouched: rollup?.domainsTouched || 0,
      errors: rollup?.errors ?? row.errorCount,
      alertsRaised: rollup?.alertsRaised || 0,
    },
  };
}
