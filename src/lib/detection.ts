/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/detection.ts.
 */
import { Prisma } from "@prisma/client";

export type SecuritySeverity = "low" | "medium" | "high" | "critical";

export type DetectionRuleMatch = {
  ruleId: string;
  ruleName: string;
  severity: SecuritySeverity;
  category: string;
  description: string;
  details?: Record<string, unknown>;
};

export type DetectionEvent = {
  eventId: string;
  ts: Date;
  severity: string;
  category: string;
  action: string;
  result?: string | null;
  outcome?: string | null;
  outcomeReason?: string | null;
  projectId?: string | null;
  agentInstanceId?: string | null;
  requestId?: string | null;
  openclaw?: {
    agentId?: string | null;
    sessionKey?: string | null;
  };
  sourceIp?: string | null;
  durationMs?: number | null;
  payload?: Prisma.InputJsonValue;
};

type PayloadMap = Record<string, unknown> | null;

function toPayloadRecord(payload?: unknown): PayloadMap {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return null;
  }
  return payload as PayloadMap;
}

function normalizeOutcome(value?: string | null): string | null {
  const raw = String(value || "").trim().toLowerCase();
  if (!raw) return null;
  if (raw === "warn" || raw === "warning") return "warn";
  if (raw === "block" || raw === "blocked" || raw === "deny") return "block";
  if (raw === "modify" || raw === "modified") return "modify";
  if (raw === "allow" || raw === "ok" || raw === "success" || raw === "submitted") return "allow";
  if (raw === "error" || raw === "failed" || raw === "fail") return "error";
  return "unknown";
}

function diagnosticType(payload: PayloadMap): string {
  if (!payload) return "";
  const value = payload.type;
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function extractCommand(payload: PayloadMap): string {
  const readCommandValue = (value: unknown): string => {
    if (typeof value === "string") return value;
    if (value && typeof value === "object" && !Array.isArray(value)) {
      const preview = (value as Record<string, unknown>).preview;
      if (typeof preview === "string") return preview;
    }
    return "";
  };

  if (!payload) return "";
  const fromRoot = readCommandValue(payload.command);
  if (fromRoot) return fromRoot;
  const params = payload.params;
  if (params && typeof params === "object" && !Array.isArray(params)) {
    const fromParams = readCommandValue((params as Record<string, unknown>).command);
    if (fromParams) return fromParams;
  }
  return "";
}

function extractPotentialIoc(payload: PayloadMap): { iocType?: string; iocValue?: string } {
  if (!payload) return {};
  const url =
    (typeof payload.url === "string" ? payload.url : "") ||
    (payload.params && typeof payload.params === "object" && !Array.isArray(payload.params)
      ? (typeof (payload.params as Record<string, unknown>).url === "string"
          ? String((payload.params as Record<string, unknown>).url)
          : "")
      : "");
  if (url.startsWith("http://") || url.startsWith("https://")) {
    return { iocType: "url", iocValue: url };
  }

  const path =
    (typeof payload.path === "string" ? payload.path : "") ||
    (payload.params && typeof payload.params === "object" && !Array.isArray(payload.params)
      ? (typeof (payload.params as Record<string, unknown>).path === "string"
          ? String((payload.params as Record<string, unknown>).path)
          : "")
      : "");
  if (path && (path.includes(".env") || path.includes(".ssh") || path.includes("id_rsa"))) {
    return { iocType: "path", iocValue: path };
  }
  return {};
}

function containsSuspiciousPattern(command: string): boolean {
  const c = command.toLowerCase();
  return (
    c.includes("rm -rf") ||
    c.includes("curl ") ||
    c.includes("wget ") ||
    c.includes("python -c") ||
    c.includes("bash -i") ||
    c.includes("nc ") ||
    c.includes("ssh ")
  );
}

function isBenignProbeCommand(command: string): boolean {
  const c = command.trim().toLowerCase();
  if (!c) return false;
  return (
    c.startsWith("which ") ||
    c.startsWith("command -v ") ||
    c.startsWith("type ") ||
    c.startsWith("test ") ||
    c.startsWith("[ ") ||
    c.startsWith("grep -q ") ||
    c.startsWith("ls ")
  );
}

function outcomeBaseRisk(outcome: string | null, severity: string): number {
  if (outcome === "block") return 75;
  if (outcome === "warn") return 38;
  if (outcome === "error") return 60;
  if (outcome === "modify") return 45;
  if (severity === "error") return 55;
  if (severity === "warn") return 40;
  if (severity === "debug") return 8;
  return 12;
}

/**
 * Applies deterministic detection heuristics and computes event risk score.
 *
 * Returns matched rules, final normalized risk score, and optional IoC extraction.
 */
export function evaluateDetections(event: DetectionEvent): {
  matches: DetectionRuleMatch[];
  riskScore: number;
  iocType?: string;
  iocValue?: string;
} {
  const payload = toPayloadRecord(event.payload);
  const normalizedOutcome = normalizeOutcome(event.outcome) || normalizeOutcome(event.result);
  const diagType = diagnosticType(payload);
  const ioc = extractPotentialIoc(payload);
  const matches: DetectionRuleMatch[] = [];
  let risk = outcomeBaseRisk(normalizedOutcome, event.severity);

  const command = extractCommand(payload);
  if (event.category === "tool" && command && containsSuspiciousPattern(command)) {
    risk += 20;
    matches.push({
      ruleId: "tool.exec.suspicious-pattern",
      ruleName: "Suspicious command pattern",
      severity: "high",
      category: "command",
      description: "Command contains shell/network patterns frequently linked to abuse",
      details: { command: command.slice(0, 240), action: event.action },
    });
  }

  if (event.category === "policy" && normalizedOutcome === "block") {
    matches.push({
      ruleId: "policy.blocked-action",
      ruleName: "Policy blocked action",
      severity: "medium",
      category: "policy",
      description: "Policy engine denied an action",
      details: { reason: event.outcomeReason ?? "policy block" },
    });
  }

  if (event.category === "policy" && normalizedOutcome === "warn") {
    matches.push({
      ruleId: "policy.warned-action",
      ruleName: "Policy warned action",
      severity: "low",
      category: "policy",
      description: "Policy engine flagged an action with warn mode",
      details: { reason: event.outcomeReason ?? "policy warn" },
    });
  }

  if (
    event.category === "session" &&
    event.action === "agent_end" &&
    (normalizedOutcome === "error" || payload?.success === false)
  ) {
    risk += 24;
    matches.push({
      ruleId: "session.run-failure",
      ruleName: "Agent run failed",
      severity: "high",
      category: "runtime",
      description: "Agent run ended with failure",
      details: { error: event.outcomeReason ?? payload?.error ?? null },
    });
  }

  if (event.category === "diagnostic" && (event.action === "session.stuck" || diagType === "session.stuck")) {
    const ageMs = typeof payload?.ageMs === "number" ? payload.ageMs : null;
    if (typeof ageMs === "number" && ageMs > 0) {
      risk += ageMs > 600_000 ? 30 : 20;
    } else {
      risk += 20;
    }
    matches.push({
      ruleId: "session.stuck",
      ruleName: "Session stuck",
      severity: ageMs && ageMs > 600_000 ? "critical" : "high",
      category: "runtime",
      description: "Session appears stuck in processing/waiting state",
      details: { ageMs, state: payload?.state ?? null },
    });
  }

  if (event.category === "diagnostic" && (event.action === "webhook.error" || diagType === "webhook.error")) {
    risk += 14;
    matches.push({
      ruleId: "automation.webhook-error",
      ruleName: "Webhook processing error",
      severity: "medium",
      category: "automation",
      description: "Webhook-triggered autonomous execution failed",
      details: {
        channel: payload?.channel ?? null,
        error: payload?.error ?? event.outcomeReason ?? null,
      },
    });
  }

  if (event.category === "diagnostic" && (event.action === "tool.loop" || diagType === "tool.loop")) {
    risk += 18;
    matches.push({
      ruleId: "tool.loop-detected",
      ruleName: "Tool loop detected",
      severity: payload?.level === "critical" ? "critical" : "high",
      category: "runtime",
      description: "OpenClaw loop detector flagged repetitive tool execution",
      details: {
        toolName: payload?.toolName ?? null,
        detector: payload?.detector ?? null,
        count: payload?.count ?? null,
      },
    });
  }

  if (normalizedOutcome === "error") {
    const reason = String(event.outcomeReason || "").toLowerCase();
    const isToolExecAfterCall = event.category === "tool" && event.action === "after_tool_call";
    const suspiciousExecError =
      isToolExecAfterCall &&
      containsSuspiciousPattern(command) &&
      !isBenignProbeCommand(command);
    const likelyBenignExitOne =
      isToolExecAfterCall &&
      reason.includes("exited with code 1") &&
      isBenignProbeCommand(command);

    if (suspiciousExecError) {
      matches.push({
        ruleId: "runtime.error",
        ruleName: "Runtime execution error",
        severity: "medium",
        category: "runtime",
        description: "Suspicious command failed during execution",
        details: { action: event.action, category: event.category, command: command.slice(0, 240) },
      });
    } else if (likelyBenignExitOne) {
      risk = Math.max(0, risk - 40);
    } else {
      risk = Math.max(0, risk - 35);
    }
  }

  if (event.durationMs && event.durationMs > 30_000) {
    risk += 10;
    matches.push({
      ruleId: "runtime.long-duration",
      ruleName: "Long running action",
      severity: "medium",
      category: "runtime",
      description: "Action duration exceeded 30 seconds",
      details: { durationMs: event.durationMs },
    });
  }

  const riskScore = Math.min(100, Math.max(0, Math.round(risk)));
  return {
    matches,
    riskScore,
    iocType: ioc.iocType,
    iocValue: ioc.iocValue,
  };
}

/**
 * Maps numeric risk score into default alert severity bands.
 */
export function defaultSeverityFromRisk(riskScore: number): SecuritySeverity {
  if (riskScore >= 80) return "critical";
  if (riskScore >= 65) return "high";
  if (riskScore >= 45) return "medium";
  return "low";
}
