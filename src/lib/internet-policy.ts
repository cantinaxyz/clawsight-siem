/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/internet-policy.ts.
 */
export type InternetDefaultAction = "allow" | "block";
export type InternetRuleMatchType = "exact" | "subdomain" | "wildcard";
export type InternetRuleAction = "allow" | "block" | "warn";
export type InternetWarnBehavior = "log_only" | "require_confirmation" | "alert";

export type InternetRule = {
  id: string;
  pattern: string;
  matchType: InternetRuleMatchType;
  action: InternetRuleAction;
  warnBehavior?: InternetWarnBehavior;
};

export type ParsedInternetRuleMatch = {
  matchType: InternetRuleMatchType;
  pattern: string;
};

export type InternetPolicyPreview = {
  action: InternetRuleAction;
  matchedRuleIndex: number | null;
  matchedRule: InternetRule | null;
  reason: string;
};

/**
 * Creates a stable client-side id for internet policy rules.
 */
export function createInternetRuleId(): string {
  const randomUuid = typeof crypto !== "undefined" && "randomUUID" in crypto
    ? crypto.randomUUID()
    : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  return `rule_${randomUuid.replace(/-/g, "").slice(0, 16)}`;
}

export function normalizeInternetPattern(raw: string): string {
  const trimmed = raw.trim().toLowerCase();
  if (!trimmed) return "";
  const withoutScheme = trimmed.replace(/^[a-z]+:\/\//, "");
  const withoutPath = withoutScheme.replace(/[/?#].*$/, "");
  return withoutPath.replace(/\.$/, "");
}

/**
 * Normalizes/validates an internet rule, filling defaults where fields are missing.
 */
export function normalizeInternetRule(rule: Partial<InternetRule>): InternetRule {
  const action = rule.action === "allow" || rule.action === "warn" || rule.action === "block"
    ? rule.action
    : "allow";
  const matchType = rule.matchType === "exact" || rule.matchType === "subdomain" || rule.matchType === "wildcard"
    ? rule.matchType
    : "subdomain";
  const warnBehavior =
    rule.warnBehavior === "alert" || rule.warnBehavior === "require_confirmation" || rule.warnBehavior === "log_only"
      ? rule.warnBehavior
      : "log_only";
  return {
    id: rule.id?.trim() || createInternetRuleId(),
    pattern: normalizeInternetPattern(rule.pattern ?? ""),
    matchType,
    action,
    warnBehavior: action === "warn" ? warnBehavior : undefined,
  };
}

/**
 * Normalizes and filters an unknown rules payload into valid internet rules.
 */
export function normalizeInternetRules(rules: unknown): InternetRule[] {
  if (!Array.isArray(rules)) return [];
  return rules
    .map((rule) => normalizeInternetRule((rule ?? {}) as Partial<InternetRule>))
    .filter((rule) => Boolean(rule.pattern));
}

/**
 * Serializes a match tuple (`type + pattern`) into a stable rule payload string.
 */
export function serializeInternetRuleMatch(matchType: InternetRuleMatchType, pattern: string): string {
  return `${matchType}:${normalizeInternetPattern(pattern)}`;
}

/**
 * Parses serialized rule-match input into typed rule fields.
 */
export function parseInternetRuleMatch(raw: string): ParsedInternetRuleMatch {
  const value = raw.trim().toLowerCase();
  const separator = value.indexOf(":");
  if (separator > 0) {
    const maybeType = value.slice(0, separator);
    const pattern = normalizeInternetPattern(value.slice(separator + 1));
    if (
      (maybeType === "exact" || maybeType === "subdomain" || maybeType === "wildcard") &&
      pattern
    ) {
      return {
        matchType: maybeType,
        pattern,
      };
    }
  }
  return {
    matchType: "subdomain",
    pattern: normalizeInternetPattern(value),
  };
}

function wildcardToRegex(pattern: string): RegExp {
  const escaped = pattern
    .split("*")
    .map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
    .join(".*");
  return new RegExp(`^${escaped}$`, "i");
}

/**
 * Evaluates whether a domain matches a rule pattern using exact/subdomain/wildcard mode.
 */
export function domainMatchesRulePattern(
  domain: string,
  matchType: InternetRuleMatchType,
  pattern: string,
): boolean {
  const normalizedDomain = normalizeInternetPattern(domain);
  const normalizedPattern = normalizeInternetPattern(pattern);
  if (!normalizedDomain || !normalizedPattern) return false;
  if (matchType === "exact") {
    return normalizedDomain === normalizedPattern;
  }
  if (matchType === "subdomain") {
    return normalizedDomain === normalizedPattern || normalizedDomain.endsWith(`.${normalizedPattern}`);
  }
  return wildcardToRegex(normalizedPattern).test(normalizedDomain);
}

/**
 * Evaluates a full `InternetRule` against a target domain.
 */
export function domainMatchesInternetRule(domain: string, rule: InternetRule): boolean {
  return domainMatchesRulePattern(domain, rule.matchType, rule.pattern);
}

/**
 * Evaluates a domain/url against ordered internet rules and default behavior.
 */
export function evaluateInternetPolicy(
  domainOrUrl: string,
  rules: InternetRule[],
  defaultAction: InternetDefaultAction,
  warnUnknownDomains: boolean,
): InternetPolicyPreview {
  const normalized = normalizeInternetPattern(domainOrUrl);
  if (!normalized) {
    return {
      action: defaultAction,
      matchedRuleIndex: null,
      matchedRule: null,
      reason: "No domain detected in input.",
    };
  }

  for (let index = 0; index < rules.length; index += 1) {
    const rule = normalizeInternetRule(rules[index]);
    if (domainMatchesInternetRule(normalized, rule)) {
      return {
        action: rule.action,
        matchedRuleIndex: index,
        matchedRule: rule,
        reason: `Matched rule #${index + 1}.`,
      };
    }
  }

  if (warnUnknownDomains) {
    return {
      action: "warn",
      matchedRuleIndex: null,
      matchedRule: null,
      reason: "No rule matched; warn on unknown domains is enabled.",
    };
  }

  return {
    action: defaultAction,
    matchedRuleIndex: null,
    matchedRule: null,
    reason: "No rule matched; default action applied.",
  };
}
