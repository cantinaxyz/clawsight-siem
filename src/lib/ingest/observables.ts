/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/ingest/observables.ts.
 */
import crypto from "node:crypto";

const URL_RE = /https?:\/\/[^\s"'<>]+/gi;
const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
const IPV6_RE = /\b(?:[a-f0-9]{1,4}:){2,7}[a-f0-9]{1,4}\b/gi;
const IPV4_EXACT_RE = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
const IPV6_EXACT_RE = /^(?:[a-f0-9]{1,4}:){2,7}[a-f0-9]{1,4}$/i;
const DOMAIN_EXACT_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const COMMON_TLDS = new Set([
  "com",
  "org",
  "net",
  "edu",
  "gov",
  "mil",
  "int",
  "io",
  "ai",
  "app",
  "dev",
  "co",
  "biz",
  "info",
  "me",
  "xyz",
  "site",
  "online",
  "cloud",
  "tech",
  "store",
  "news",
  "wiki",
  "finance",
  "agency",
  "digital",
  "blog",
]);
const CODEISH_DOMAIN_LABELS = new Set([
  "np",
  "pd",
  "dt",
  "iloc",
  "tail",
  "head",
  "std",
  "sqrt",
  "replace",
  "dropna",
  "isoformat",
  "timedelta",
  "date",
  "index",
  "min",
  "max",
  "nan",
  "inf",
  "params",
  "event",
  "output",
  "input",
  "value",
]);
const FILE_EXTENSIONS = new Set([
  "json",
  "yaml",
  "yml",
  "toml",
  "ini",
  "conf",
  "lock",
  "md",
  "txt",
  "log",
  "csv",
  "xml",
  "sql",
  "db",
  "sqlite",
  "js",
  "ts",
  "mjs",
  "cjs",
  "py",
  "sh",
  "ps1",
  "bat",
  "pdf",
  "png",
  "jpg",
  "jpeg",
  "gif",
  "webp",
  "svg",
]);

export type ExtractedObservable = {
  kind: string;
  value: string;
  valueHash: string;
  confidence?: number;
};

type ExtractObservableInput = {
  sourceIp?: string | null;
  iocType?: string | null;
  iocValue?: string | null;
  payloadRedacted?: unknown;
};

function hashValue(value: string): string {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function normalizeValue(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length <= 280) return trimmed;
  return `${trimmed.slice(0, 280)}…`;
}

function pushObservable(
  store: Map<string, ExtractedObservable>,
  kind: string,
  value: string | null | undefined,
  confidence = 50,
) {
  if (!value) return;
  const normalized = normalizeValue(value);
  if (!normalized) return;
  const key = `${kind}:${normalized.toLowerCase()}`;
  if (store.has(key)) return;
  store.set(key, {
    kind,
    value: normalized,
    valueHash: hashValue(normalized.toLowerCase()),
    confidence,
  });
}

function normalizeDomain(input: string): string {
  let value = input.trim().toLowerCase();
  if (!value) return "";
  if (/^https?:\/\//i.test(value)) {
    try {
      value = new URL(value).hostname.toLowerCase();
    } catch {
      // keep raw value
    }
  }
  value = value.replace(/\.$/, "");
  if (value.includes(":") && !value.includes("::")) {
    value = value.replace(/:\d+$/, "");
  }
  return value;
}

function isIpv4(input: string): boolean {
  return IPV4_EXACT_RE.test(input.trim());
}

function isIpv6(input: string): boolean {
  return IPV6_EXACT_RE.test(input.trim());
}

type DomainSource = "url_host" | "key_hint";

function isValidDomainCandidate(domain: string, source: DomainSource): boolean {
  if (!domain) return false;
  if (isIpv4(domain) || isIpv6(domain)) return false;
  if (domain === "localhost") return source === "url_host";
  if (!domain.includes(".")) return false;
  if (domain.includes("_")) return false;
  if (!DOMAIN_EXACT_RE.test(domain)) return false;

  const labels = domain.split(".").filter(Boolean);
  if (labels.length < 2) return false;

  if (source === "key_hint") {
    const codeishHits = labels.reduce((acc, label) => acc + (CODEISH_DOMAIN_LABELS.has(label) ? 1 : 0), 0);
    if (codeishHits >= 2) return false;
    const tld = labels[labels.length - 1];
    if (!(tld.length === 2 || COMMON_TLDS.has(tld))) {
      return false;
    }
  }
  return true;
}

function pushDomain(
  store: Map<string, ExtractedObservable>,
  value: string,
  confidence = 60,
  source: DomainSource = "key_hint",
) {
  const domain = normalizeDomain(value);
  if (!domain) return;
  if (looksLikeFileNameToken(domain)) return;
  if (!isValidDomainCandidate(domain, source)) return;
  pushObservable(store, "domain", domain, confidence);
}

function looksLikeFileNameToken(input: string): boolean {
  const value = normalizeDomain(input);
  if (!value) return false;
  if (value.includes("/") || value.includes("\\") || value.startsWith(".")) return true;
  const parts = value.split(".");
  if (parts.length < 2) return false;
  const ext = parts[parts.length - 1];
  return FILE_EXTENSIONS.has(ext);
}

function pushIp(store: Map<string, ExtractedObservable>, value: string, confidence = 70) {
  const ip = value.trim();
  if (!ip) return;
  pushObservable(store, "ip", ip, confidence);
}

function pushUrl(store: Map<string, ExtractedObservable>, value: string, confidence = 80) {
  const url = value.trim();
  if (!url) return;
  if (!/^https?:\/\//i.test(url)) return;
  pushObservable(store, "url", url, confidence);
  try {
    const parsed = new URL(url);
    if (parsed.hostname) {
      if (isIpv4(parsed.hostname) || isIpv6(parsed.hostname)) {
        pushIp(store, parsed.hostname, 75);
      } else {
        pushDomain(store, parsed.hostname, 70, "url_host");
      }
    }
  } catch {
    // Ignore malformed URL.
  }
}

function collectFromString(input: string, store: Map<string, ExtractedObservable>) {
  for (const url of input.match(URL_RE) ?? []) {
    pushUrl(store, url, 80);
  }
  for (const ip of input.match(IPV4_RE) ?? []) {
    pushIp(store, ip, 70);
  }
  for (const ip of input.match(IPV6_RE) ?? []) {
    pushIp(store, ip, 65);
  }
}

function collectFromKeyHint(
  key: string,
  value: string,
  store: Map<string, ExtractedObservable>,
) {
  const normalizedKey = key.trim().toLowerCase();
  const trimmed = value.trim();
  if (!trimmed) return;

  if (/(url|uri|endpoint|href|link|target)/i.test(normalizedKey)) {
    pushUrl(store, trimmed, 85);
  }

  if (/(domain|hostname|host)/i.test(normalizedKey)) {
    if (/^https?:\/\//i.test(trimmed)) {
      pushUrl(store, trimmed, 80);
    } else if (isIpv4(trimmed) || isIpv6(trimmed)) {
      pushIp(store, trimmed, 80);
    } else {
      pushDomain(store, trimmed, 80, "key_hint");
    }
  }

  if (/(^|_)(ip|sourceip|destip|destinationip|remoteip)(_|$)/i.test(normalizedKey)) {
    if (isIpv4(trimmed) || isIpv6(trimmed)) {
      pushIp(store, trimmed, 85);
    }
  }

  if (/(target|to|recipient|destination)/i.test(normalizedKey) && !/(https?:\/\/|\.)/i.test(trimmed)) {
    pushObservable(store, "destination", trimmed, 45);
  }

  if (/(path|file|workdir|cwd)/i.test(normalizedKey)) {
    pushObservable(store, "path", trimmed, 50);
  }
}

function visitPayload(
  value: unknown,
  store: Map<string, ExtractedObservable>,
  depth = 0,
  keyHint = "",
) {
  if (depth > 5 || value == null) return;

  if (typeof value === "string") {
    if (keyHint) {
      collectFromKeyHint(keyHint, value, store);
    }
    if (keyHint && /(path|file|workdir|cwd|dir|directory)/i.test(keyHint)) {
      return;
    }
    collectFromString(value, store);
    return;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return;
  }
  if (Array.isArray(value)) {
    for (const entry of value.slice(0, 60)) {
      visitPayload(entry, store, depth + 1, keyHint);
    }
    return;
  }
  if (typeof value !== "object") {
    return;
  }
  const record = value as Record<string, unknown>;
  const entries = Object.entries(record).slice(0, 80);
  for (const [key, child] of entries) {
    if (typeof child === "string") {
      collectFromKeyHint(key, child, store);
    }
    visitPayload(child, store, depth + 1, key);
  }
}

/**
 * Extracts deduplicated observables from redacted payloads and top-level metadata.
 *
 * Observable extraction is intentionally bounded (depth/collection limits) to avoid
 * untrusted payload blowups during ingestion.
 */
export function extractObservables(input: ExtractObservableInput): ExtractedObservable[] {
  const store = new Map<string, ExtractedObservable>();

  if (input.sourceIp) {
    pushObservable(store, "ip", input.sourceIp, 90);
  }

  if (input.iocType && input.iocValue) {
    pushObservable(store, input.iocType, input.iocValue, 95);
  }

  visitPayload(input.payloadRedacted, store);
  return [...store.values()];
}
