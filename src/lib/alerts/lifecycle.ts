/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/alerts/lifecycle.ts.
 */
export const ALERT_STATUSES = [
  "open",
  "acknowledged",
  "resolved",
  "false_positive",
] as const;

export type AlertStatus = (typeof ALERT_STATUSES)[number];

export const ALERT_CLASSIFICATIONS = [
  "malicious_input",
  "capability_abuse",
  "policy_misconfig",
  "agent_bug",
  "benign_anomaly",
] as const;

export type AlertClassification = (typeof ALERT_CLASSIFICATIONS)[number];

const TERMINAL = new Set<AlertStatus>(["resolved", "false_positive"]);

const TRANSITIONS: Record<AlertStatus, ReadonlySet<AlertStatus>> = {
  open: new Set(["acknowledged", "resolved", "false_positive"]),
  acknowledged: new Set(["open", "resolved", "false_positive"]),
  resolved: new Set(),
  false_positive: new Set(),
};

export function normalizeAlertStatus(value: unknown): AlertStatus | null {
  const raw = String(value || "").trim().toLowerCase();
  if ((ALERT_STATUSES as readonly string[]).includes(raw)) return raw as AlertStatus;
  if (raw === "investigating") return "acknowledged";
  if (raw === "closed") return "resolved";
  return null;
}

export function isTerminalStatus(status: AlertStatus): boolean {
  return TERMINAL.has(status);
}

export function canTransitionAlertStatus(current: AlertStatus, next: AlertStatus): boolean {
  if (current === next) return true;
  return TRANSITIONS[current].has(next);
}

export function normalizeAlertClassification(value: unknown): AlertClassification | null {
  const raw = String(value || "").trim().toLowerCase();
  if ((ALERT_CLASSIFICATIONS as readonly string[]).includes(raw)) {
    return raw as AlertClassification;
  }
  return null;
}

export function requiresResolutionNote(next: AlertStatus): boolean {
  return next === "resolved" || next === "false_positive";
}
