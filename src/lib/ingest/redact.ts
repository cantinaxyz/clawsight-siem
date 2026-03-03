/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/ingest/redact.ts.
 */
import crypto from "node:crypto";
import { Prisma } from "@prisma/client";

const SENSITIVE_KEY_RE =
  /(token|secret|password|passphrase|api[_-]?key|authorization|cookie|set-cookie|private[_-]?key|access[_-]?key|refresh[_-]?token|session[_-]?key)/i;
const HASH_ONLY_KEY_RE = /(command|content|body|stdout|stderr|result)/i;
const BEARER_TOKEN_RE = /\bbearer\s+[a-z0-9._~+/-]+=*/gi;
const PRIVATE_KEY_BLOCK_RE = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g;
const API_KEY_TOKEN_RE = /\b(?:sk|rk|pk|ghp|gho|ghu|xoxb|xoxp|xoxa|xoxr)[_-][a-z0-9_-]{12,}\b/gi;
const HIGH_ENTROPY_RE = /^[A-Za-z0-9+/_=-]{48,}$/;
const MAX_STRING = 800;
const MAX_DEPTH = 6;
const MAX_KEYS = 80;
const MAX_ARRAY = 80;

function hashSha256(value: string): string {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function toJsonText(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function normalizeString(raw: string): string {
  if (raw.length <= MAX_STRING) return raw;
  return `${raw.slice(0, MAX_STRING)}…(${raw.length} chars)`;
}

function redactSensitiveString(raw: string): string {
  let out = raw;
  out = out.replace(PRIVATE_KEY_BLOCK_RE, "[REDACTED_PRIVATE_KEY]");
  out = out.replace(BEARER_TOKEN_RE, "Bearer [REDACTED]");
  out = out.replace(API_KEY_TOKEN_RE, "[REDACTED_API_KEY]");
  if (out !== raw) {
    return out;
  }

  const compact = raw.trim();
  if (
    compact.length >= 64 &&
    !compact.includes(" ") &&
    HIGH_ENTROPY_RE.test(compact) &&
    /[A-Za-z]/.test(compact) &&
    /\d/.test(compact)
  ) {
    return `[REDACTED_SECRET:${compact.length}]`;
  }
  return out;
}

function normalizePrimitive(value: unknown): unknown {
  if (value == null) return value;
  if (typeof value === "string") return normalizeString(value);
  if (typeof value === "number" || typeof value === "boolean") return value;
  return String(value);
}

function redactNode(value: unknown, key: string | null, depth: number): unknown {
  if (depth > MAX_DEPTH) {
    return "[TRUNCATED_DEPTH]";
  }

  if (key && SENSITIVE_KEY_RE.test(key)) {
    return "[REDACTED]";
  }

  if (typeof value === "string") {
    if (key && HASH_ONLY_KEY_RE.test(key)) {
      const safePreview = normalizeString(redactSensitiveString(value));
      return {
        hash: hashSha256(value),
        length: value.length,
        preview: safePreview.slice(0, Math.min(120, safePreview.length)),
      };
    }
    return normalizeString(redactSensitiveString(value));
  }

  if (Array.isArray(value)) {
    const out = value.slice(0, MAX_ARRAY).map((item) => redactNode(item, null, depth + 1));
    if (value.length > MAX_ARRAY) {
      out.push(`[TRUNCATED_ARRAY:${value.length - MAX_ARRAY}]`);
    }
    return out;
  }

  if (!value || typeof value !== "object") {
    return normalizePrimitive(value);
  }

  const record = value as Record<string, unknown>;
  const entries = Object.entries(record);
  const out: Record<string, unknown> = {};
  for (const [childKey, childValue] of entries.slice(0, MAX_KEYS)) {
    out[childKey] = redactNode(childValue, childKey, depth + 1);
  }
  if (entries.length > MAX_KEYS) {
    out._truncatedKeys = entries.length - MAX_KEYS;
  }
  return out;
}

function toJsonValue(value: unknown): Prisma.InputJsonValue | typeof Prisma.JsonNull {
  if (value === null || value === undefined) {
    return Prisma.JsonNull;
  }
  return value as Prisma.InputJsonValue;
}

export type RedactedPayload = {
  payloadRedacted: Prisma.InputJsonValue | typeof Prisma.JsonNull;
  payloadHash: string | null;
  payloadBytes: number | null;
};

export function redactPayload(payload: unknown): RedactedPayload {
  if (payload === null || payload === undefined) {
    return {
      payloadRedacted: Prisma.JsonNull,
      payloadHash: null,
      payloadBytes: null,
    };
  }

  const raw = toJsonText(payload);
  const redacted = redactNode(payload, null, 0);

  return {
    payloadRedacted: toJsonValue(redacted),
    payloadHash: hashSha256(raw),
    payloadBytes: Buffer.byteLength(raw, "utf8"),
  };
}
