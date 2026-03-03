/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/agents/identity.ts.
 */
export type AgentIdentityInput = {
  projectId?: string | null;
  agentInstanceId?: string | null;
  agentName?: string | null;
  openclawAgentId?: string | null;
  openclawSessionKey?: string | null;
  openclawSessionId?: string | null;
};

export type ManagedAgentKeyKind = "inst" | "sid" | "oc" | "sess";

export type ManagedAgentKeyParts = {
  kind: ManagedAgentKeyKind;
  projectId: string;
  value: string;
};

function clean(value: string | null | undefined): string {
  return String(value || "").trim();
}

function projectSegment(projectId?: string | null): string {
  const normalized = clean(projectId);
  return normalized || "default";
}

function sanitizeSegment(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

/**
 * Derives the canonical managed-agent key from available identity signals.
 *
 * Key precedence: `agentInstanceId` -> `openclawSessionId` -> `openclawAgentId` -> `openclawSessionKey`.
 */
export function deriveManagedAgentKey(input: AgentIdentityInput): string {
  const project = projectSegment(input.projectId);
  const instanceId = clean(input.agentInstanceId);
  if (instanceId) {
    return `inst:${project}:${sanitizeSegment(instanceId)}`;
  }

  const sessionId = clean(input.openclawSessionId);
  if (sessionId) {
    return `sid:${project}:${sanitizeSegment(sessionId)}`;
  }

  const openclawAgentId = clean(input.openclawAgentId);
  if (openclawAgentId) {
    return `oc:${project}:${sanitizeSegment(openclawAgentId)}`;
  }

  const sessionKey = clean(input.openclawSessionKey) || "unknown";
  return `sess:${project}:${sanitizeSegment(sessionKey)}`;
}

/**
 * Parses a canonical managed-agent key into typed segments.
 *
 * @param agentKey String in format `kind:project:value`.
 * @returns Parsed segments or null when malformed.
 */
export function parseManagedAgentKey(agentKey?: string | null): ManagedAgentKeyParts | null {
  const raw = clean(agentKey);
  if (!raw) return null;

  const first = raw.indexOf(":");
  if (first < 0) return null;
  const second = raw.indexOf(":", first + 1);
  if (second < 0) return null;

  const kind = raw.slice(0, first);
  if (kind !== "inst" && kind !== "sid" && kind !== "oc" && kind !== "sess") {
    return null;
  }

  const projectId = clean(raw.slice(first + 1, second)) || "default";
  const value = clean(raw.slice(second + 1));
  if (!value) return null;

  return {
    kind,
    projectId,
    value,
  };
}

/**
 * Builds a human-readable display label from agent identity attributes.
 */
export function deriveManagedAgentLabel(input: AgentIdentityInput): string {
  const agentName = clean(input.agentName);
  if (agentName) return agentName;

  const instanceId = clean(input.agentInstanceId);
  if (instanceId) return instanceId;

  const sessionId = clean(input.openclawSessionId);
  if (sessionId) {
    const openclawAgentId = clean(input.openclawAgentId);
    const shortSession = sessionId.slice(0, 8);
    if (openclawAgentId) {
      return `${openclawAgentId} · ${shortSession}`;
    }
    return `session · ${shortSession}`;
  }

  const openclawAgentId = clean(input.openclawAgentId);
  if (openclawAgentId) return openclawAgentId;

  const sessionKey = clean(input.openclawSessionKey);
  if (sessionKey) return sessionKey;

  return "unknown-agent";
}
