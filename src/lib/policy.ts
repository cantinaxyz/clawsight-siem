/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/policy.ts.
 */
import crypto from "node:crypto";
import { isIP } from "node:net";
import type { PolicyRule } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { deriveManagedAgentKey } from "@/lib/agents/identity";
import { domainMatchesRulePattern, parseInternetRuleMatch } from "@/lib/internet-policy";

export type DecisionAction = "allow" | "warn" | "block" | "modify";
export type PolicyScope = "tool" | "message" | "domain" | "ip";

const URL_RE = /https?:\/\/[^\s"'<>]+/gi;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi;
const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
const IPV6_RE = /\b(?:[a-f0-9]{1,4}:){2,7}[a-f0-9]{1,4}\b/gi;
const TOKEN_RE = /[^\s"'<>]+/g;

export type ToolDecisionResult = {
  action: DecisionAction;
  reason?: string;
  params?: Record<string, unknown>;
  decisionId?: string;
  ruleId?: string;
};

export type MessageDecisionResult = {
  action: DecisionAction;
  reason?: string;
  content?: string;
  decisionId?: string;
  ruleId?: string;
};

function getDecisionId(prefix: string): string {
  return `${prefix}-${crypto.randomUUID().slice(0, 8)}`;
}

function normalize(value: unknown): string {
  return String(value ?? "").trim().toLowerCase();
}

function parseCsvEnv(value: string | undefined): string[] {
  return String(value ?? "")
    .split(",")
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);
}

function readCsvEnv(primaryKey: string, fallbackKeys: string[] = []): string[] {
  const values = [
    ...parseCsvEnv(process.env[primaryKey]),
    ...fallbackKeys.flatMap((key) => parseCsvEnv(process.env[key])),
  ];
  return [...new Set(values)];
}

const ENV_TOOL_DENYLIST = new Set(
  readCsvEnv("CLAWSIGHT_TOOL_DENYLIST", ["CLAWDSTRIKE_TOOL_DENYLIST"]),
);
const ENV_TOOL_BLOCK_PATTERNS = readCsvEnv("CLAWSIGHT_TOOL_BLOCK_PATTERNS", [
  "CLAWDSTRIKE_TOOL_BLOCK_PATTERNS",
]);
const ENV_MESSAGE_BLOCK_PHRASES = readCsvEnv("CLAWSIGHT_MESSAGE_BLOCK_PHRASES", [
  "CLAWDSTRIKE_MESSAGE_BLOCK_PHRASES",
]);

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value ?? "");
  }
}

function asAction(value: string): DecisionAction {
  if (value === "allow" || value === "warn" || value === "block" || value === "modify") {
    return value;
  }
  return "allow";
}

function getToolName(req: Record<string, unknown>): string {
  return normalize(req.toolName || req.tool || req.kind);
}

function getToolCommand(req: Record<string, unknown>): string {
  const params = asRecord(req.params);
  const command = normalize(params?.command);
  if (command) return command;
  if (!params) return "";
  return normalize(safeStringify(params));
}

function getMessageTo(req: Record<string, unknown>): string {
  return normalize(req.to);
}

function getMessageChannel(req: Record<string, unknown>): string {
  return normalize(req.channelId);
}

function getMessageContent(req: Record<string, unknown>): string {
  return normalize(req.content);
}

function includesNormalized(haystack: string, needle: string | null): boolean {
  if (!needle) return true;
  const normalizedNeedle = needle.trim().toLowerCase();
  if (!normalizedNeedle) return true;
  return haystack.includes(normalizedNeedle);
}

function normalizeDomain(value: string): string {
  return value.trim().toLowerCase().replace(/\.$/, "");
}

function normalizeIp(value: string): string {
  let candidate = value.trim().toLowerCase();
  if (!candidate) return "";

  candidate = candidate
    .replace(/^[`"'({<]+/, "")
    .replace(/[)`"'}>,;.!?]+$/, "");

  if (candidate.includes("://")) {
    try {
      const parsed = new URL(candidate);
      if (parsed.hostname) {
        candidate = parsed.hostname.toLowerCase();
      }
    } catch {
      // keep original candidate
    }
  }

  if (candidate.startsWith("[")) {
    const end = candidate.indexOf("]");
    if (end > 0) {
      candidate = candidate.slice(1, end);
    }
  } else if (candidate.endsWith("]")) {
    candidate = candidate.slice(0, -1);
  }

  const slashIdx = candidate.indexOf("/");
  if (slashIdx > 0) candidate = candidate.slice(0, slashIdx);
  const queryIdx = candidate.indexOf("?");
  if (queryIdx > 0) candidate = candidate.slice(0, queryIdx);
  const hashIdx = candidate.indexOf("#");
  if (hashIdx > 0) candidate = candidate.slice(0, hashIdx);

  candidate = candidate.replace(/%[0-9a-z_.-]+$/i, "");
  candidate = candidate.replace(/^ipv6:/i, "");

  if (isIP(candidate) !== 0) return candidate;

  if (candidate.includes(":") && candidate.indexOf(":") === candidate.lastIndexOf(":")) {
    const [hostPart, portPart] = candidate.split(":");
    if (hostPart && portPart && /^\d+$/.test(portPart) && isIP(hostPart) !== 0) {
      return hostPart;
    }
  }

  return "";
}

function addIpCandidate(value: string, store: Set<string>) {
  const ip = normalizeIp(value);
  if (!ip || isIP(ip) === 0) return;
  store.add(ip);
}

function collectTargetsFromString(input: string, domainStore: Set<string>, ipStore: Set<string>) {
  for (const url of input.match(URL_RE) ?? []) {
    try {
      const parsed = new URL(url);
      if (parsed.hostname) {
        const hostname = normalizeDomain(parsed.hostname);
        if (!hostname) continue;
        if (isIP(hostname) === 0) {
          domainStore.add(hostname);
        } else {
          addIpCandidate(hostname, ipStore);
        }
      }
    } catch {
      // Ignore malformed URL.
    }
  }
  for (const domain of input.match(DOMAIN_RE) ?? []) {
    domainStore.add(normalizeDomain(domain));
  }
  for (const ip of input.match(IPV4_RE) ?? []) {
    addIpCandidate(ip, ipStore);
  }
  for (const ip of input.match(IPV6_RE) ?? []) {
    addIpCandidate(ip, ipStore);
  }
  for (const token of input.match(TOKEN_RE) ?? []) {
    addIpCandidate(token, ipStore);
  }
}

function collectTargetsFromUnknown(
  value: unknown,
  domainStore: Set<string>,
  ipStore: Set<string>,
  depth = 0,
) {
  if (depth > 5 || value == null) return;
  if (typeof value === "string") {
    collectTargetsFromString(value, domainStore, ipStore);
    return;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return;
  }
  if (Array.isArray(value)) {
    for (const entry of value.slice(0, 80)) {
      collectTargetsFromUnknown(entry, domainStore, ipStore, depth + 1);
    }
    return;
  }
  if (typeof value === "object") {
    for (const [key, entry] of Object.entries(value as Record<string, unknown>).slice(0, 120)) {
      collectTargetsFromUnknown(entry, domainStore, ipStore, depth + 1);
      if (
        /domain|host|url|uri|endpoint|href|link|target|destination/i.test(key) &&
        typeof entry === "string"
      ) {
        collectTargetsFromString(entry, domainStore, ipStore);
      }
      if (/ip|sourceip|destip|destinationip|remoteip/i.test(key) && typeof entry === "string") {
        addIpCandidate(entry, ipStore);
      }
    }
  }
}

function extractRequestTargets(req: Record<string, unknown>): { domains: string[]; ips: string[] } {
  const domains = new Set<string>();
  const ips = new Set<string>();
  collectTargetsFromUnknown(req, domains, ips);
  return {
    domains: [...domains.values()].filter(Boolean),
    ips: [...ips.values()].filter(Boolean),
  };
}

function matchesDomainRule(rule: PolicyRule, domains: string[]): boolean {
  if (rule.scope !== "domain" || !rule.enabled) return false;
  const rawPattern = normalize(rule.contentContains);
  if (!rawPattern) {
    return domains.length > 0;
  }
  const parsed = parseInternetRuleMatch(rawPattern);
  return domains.some((domain) =>
    domainMatchesRulePattern(domain, parsed.matchType, parsed.pattern),
  );
}

function matchesIpRule(rule: PolicyRule, ips: string[]): boolean {
  if (rule.scope !== "ip" || !rule.enabled) return false;
  const needleRaw = normalize(rule.contentContains);
  if (!needleRaw) {
    return ips.length > 0;
  }
  const needles = new Set(
    needleRaw
      .split(/[,\s]+/)
      .map((candidate) => normalizeIp(candidate))
      .filter((candidate) => Boolean(candidate) && isIP(candidate) !== 0),
  );
  if (needles.size === 0) {
    return false;
  }
  return ips.some((ip) => needles.has(normalizeIp(ip)));
}

function matchesToolRule(rule: PolicyRule, req: Record<string, unknown>): boolean {
  if (rule.scope !== "tool" || !rule.enabled) return false;
  const toolName = getToolName(req);
  const command = getToolCommand(req);

  if (rule.toolName && normalize(rule.toolName) !== toolName) {
    return false;
  }
  if (rule.commandContains && !includesNormalized(command, rule.commandContains)) {
    return false;
  }
  return true;
}

function matchesMessageRule(rule: PolicyRule, req: Record<string, unknown>): boolean {
  if (rule.scope !== "message" || !rule.enabled) return false;
  const to = getMessageTo(req);
  const channelId = getMessageChannel(req);
  const content = getMessageContent(req);

  if (rule.channelId && normalize(rule.channelId) !== channelId) {
    return false;
  }
  if (rule.toContains && !includesNormalized(to, rule.toContains)) {
    return false;
  }
  if (rule.contentContains && !includesNormalized(content, rule.contentContains)) {
    return false;
  }
  return true;
}

function parseModifyParams(value: unknown): Record<string, unknown> | undefined {
  const obj = asRecord(value);
  return obj ?? undefined;
}

function applyDomainToolRule(rule: PolicyRule): ToolDecisionResult {
  const action: DecisionAction =
    rule.action === "block" || rule.action === "warn" ? rule.action : "allow";
  const ruleId = String(rule.id);
  return {
    action,
    reason: rule.reason || `${action} by domain rule ${ruleId}`,
    decisionId: getDecisionId("tool"),
    ruleId,
  };
}

function applyDomainMessageRule(rule: PolicyRule): MessageDecisionResult {
  const action: DecisionAction =
    rule.action === "block" || rule.action === "warn" ? rule.action : "allow";
  const ruleId = String(rule.id);
  return {
    action,
    reason: rule.reason || `${action} by domain rule ${ruleId}`,
    decisionId: getDecisionId("msg"),
    ruleId,
  };
}

function applyIpToolRule(rule: PolicyRule): ToolDecisionResult {
  const action: DecisionAction =
    rule.action === "block" || rule.action === "warn" ? rule.action : "allow";
  const ruleId = String(rule.id);
  return {
    action,
    reason: rule.reason || `${action} by ip rule ${ruleId}`,
    decisionId: getDecisionId("tool"),
    ruleId,
  };
}

function applyIpMessageRule(rule: PolicyRule): MessageDecisionResult {
  const action: DecisionAction =
    rule.action === "block" || rule.action === "warn" ? rule.action : "allow";
  const ruleId = String(rule.id);
  return {
    action,
    reason: rule.reason || `${action} by ip rule ${ruleId}`,
    decisionId: getDecisionId("msg"),
    ruleId,
  };
}

function applyToolRule(rule: PolicyRule, req: Record<string, unknown>): ToolDecisionResult {
  const action = asAction(rule.action);
  const ruleId = String(rule.id);
  const decisionId = getDecisionId("tool");
  if (action === "block") {
    return {
      action,
      reason: rule.reason || `blocked by rule ${ruleId}`,
      decisionId,
      ruleId,
    };
  }
  if (action === "warn") {
    return {
      action,
      reason: rule.reason || `warned by rule ${ruleId}`,
      decisionId,
      ruleId,
    };
  }
  if (action === "modify") {
    const currentParams = asRecord(req.params) ?? {};
    const patch = parseModifyParams(rule.modifyParams);
    return {
      action,
      reason: rule.reason || `modified by rule ${ruleId}`,
      params: patch ? { ...currentParams, ...patch } : currentParams,
      decisionId,
      ruleId,
    };
  }
  return {
    action: "allow",
    reason: rule.reason || undefined,
    decisionId,
    ruleId,
  };
}

function applyMessageRule(
  rule: PolicyRule,
  req: Record<string, unknown>,
): MessageDecisionResult {
  const action = asAction(rule.action);
  const ruleId = String(rule.id);
  const decisionId = getDecisionId("msg");
  if (action === "block") {
    return {
      action,
      reason: rule.reason || `blocked by rule ${ruleId}`,
      decisionId,
      ruleId,
    };
  }
  if (action === "warn") {
    return {
      action,
      reason: rule.reason || `warned by rule ${ruleId}`,
      decisionId,
      ruleId,
    };
  }
  if (action === "modify") {
    const originalContent = String(req.content || "");
    return {
      action,
      reason: rule.reason || `modified by rule ${ruleId}`,
      content: rule.modifyContent ?? originalContent,
      decisionId,
      ruleId,
    };
  }
  return {
    action: "allow",
    reason: rule.reason || undefined,
    decisionId,
    ruleId,
  };
}

function getEnvToolDecision(req: Record<string, unknown>): ToolDecisionResult | null {
  const toolName = getToolName(req);
  if (toolName && ENV_TOOL_DENYLIST.has(toolName)) {
    return {
      action: "block",
      reason: `blocked by environment tool denylist (${toolName})`,
      decisionId: getDecisionId("tool"),
      ruleId: "env:tool_denylist",
    };
  }

  const command = getToolCommand(req);
  if (command) {
    for (const pattern of ENV_TOOL_BLOCK_PATTERNS) {
      if (command.includes(pattern)) {
        return {
          action: "block",
          reason: `blocked by environment tool block pattern (${pattern})`,
          decisionId: getDecisionId("tool"),
          ruleId: "env:tool_block_pattern",
        };
      }
    }
  }

  return null;
}

function getEnvMessageDecision(req: Record<string, unknown>): MessageDecisionResult | null {
  const content = getMessageContent(req);
  if (!content) return null;

  for (const phrase of ENV_MESSAGE_BLOCK_PHRASES) {
    if (content.includes(phrase)) {
      return {
        action: "block",
        reason: `blocked by environment message block phrase (${phrase})`,
        decisionId: getDecisionId("msg"),
        ruleId: "env:message_block_phrase",
      };
    }
  }

  return null;
}

function getRequestManagedAgentKey(req: Record<string, unknown>): string | null {
  const explicit = normalize(req.managedAgentKey);
  if (explicit) return explicit;

  const projectId = normalize(req.projectId) || null;
  const agentInstanceId = normalize(req.agentInstanceId) || null;
  const openclawAgentId =
    normalize(req.openclawAgentId) ||
    normalize(req.agentId) ||
    null;
  const openclawSessionKey =
    normalize(req.openclawSessionKey) ||
    normalize(req.sessionKey) ||
    normalize(req.conversationId) ||
    null;
  const openclawSessionId =
    normalize(req.openclawSessionId) ||
    normalize(req.sessionId) ||
    null;

  if (!agentInstanceId && !openclawAgentId && !openclawSessionId && !openclawSessionKey) {
    return null;
  }

  return deriveManagedAgentKey({
    projectId,
    agentInstanceId,
    openclawAgentId,
    openclawSessionKey,
    openclawSessionId,
  });
}

async function getScopedRules(
  scopes: PolicyScope[],
  managedAgentKey: string | null,
): Promise<PolicyRule[]> {
  const globalRules = await prisma.policyRule.findMany({
    where: {
      scope: { in: scopes },
      enabled: true,
      scopeLevel: "global",
    },
    orderBy: [{ priority: "asc" }, { id: "asc" }],
  });

  if (!managedAgentKey) {
    return globalRules;
  }

  const agentRules = await prisma.policyRule.findMany({
    where: {
      scope: { in: scopes },
      enabled: true,
      scopeLevel: "agent",
      managedAgentKey,
    },
    orderBy: [{ priority: "asc" }, { id: "asc" }],
  });

  return [...agentRules, ...globalRules];
}

/**
 * Evaluates a tool decision against agent-scoped + global static policy rules.
 *
 * Matching order is deterministic by rule priority/id and scope precedence:
 * domain -> ip -> tool.
 */
export async function evaluateToolDecision(req: Record<string, unknown>): Promise<ToolDecisionResult> {
  const envDecision = getEnvToolDecision(req);
  if (envDecision) {
    return envDecision;
  }
  const managedAgentKey = getRequestManagedAgentKey(req);
  const rules = await getScopedRules(["domain", "ip", "tool"], managedAgentKey);
  const targets = extractRequestTargets(req);
  for (const rule of rules) {
    if (rule.scope === "domain" && matchesDomainRule(rule, targets.domains)) {
      return applyDomainToolRule(rule);
    }
    if (rule.scope === "ip" && matchesIpRule(rule, targets.ips)) {
      return applyIpToolRule(rule);
    }
    if (matchesToolRule(rule, req)) {
      return applyToolRule(rule, req);
    }
  }
  return { action: "allow" };
}

/**
 * Evaluates outbound message decisions against static policy rules.
 *
 * Matching order is deterministic by rule priority/id and scope precedence:
 * domain -> ip -> message.
 */
export async function evaluateMessageDecision(req: Record<string, unknown>): Promise<MessageDecisionResult> {
  const envDecision = getEnvMessageDecision(req);
  if (envDecision) {
    return envDecision;
  }
  const managedAgentKey = getRequestManagedAgentKey(req);
  const rules = await getScopedRules(["domain", "ip", "message"], managedAgentKey);
  const targets = extractRequestTargets(req);
  for (const rule of rules) {
    if (rule.scope === "domain" && matchesDomainRule(rule, targets.domains)) {
      return applyDomainMessageRule(rule);
    }
    if (rule.scope === "ip" && matchesIpRule(rule, targets.ips)) {
      return applyIpMessageRule(rule);
    }
    if (matchesMessageRule(rule, req)) {
      return applyMessageRule(rule, req);
    }
  }
  return { action: "allow" };
}
