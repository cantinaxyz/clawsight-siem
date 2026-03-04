/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/safety-config.ts.
 */
import { prisma } from "@/lib/prisma";
import {
  loadIntentPolicyConfig,
  saveIntentPolicyConfig,
  type IntentPolicyConfig,
} from "@/lib/intent-policy";
import {
  createInternetRuleId,
  normalizeInternetPattern,
  normalizeInternetRules,
  serializeInternetRuleMatch,
  type InternetDefaultAction,
  type InternetRule,
  type InternetWarnBehavior,
} from "@/lib/internet-policy";

export type SafetyMode = "relaxed" | "balanced" | "strict";
export type TernaryMode = "allow" | "warn" | "block";

export type SafetyConfig = {
  mode: SafetyMode;
  actions: {
    runCommands: TernaryMode;
    allowedCommands: string[];
    warnedCommands: string[];
    blockedCommands: string[];
    writeFiles: TernaryMode;
    installDownloads: TernaryMode;
    accessSecrets: TernaryMode;
    payments: TernaryMode;
  };
  internet: {
    defaultAction: InternetDefaultAction;
    rules: InternetRule[];
    warnUnknownDomains: boolean;
    warnUnknownBehavior: InternetWarnBehavior;
    blockDirectIpNavigation: boolean;
    allowHttpsOnly: boolean;
  };
  intentPolicy: IntentPolicyConfig;
};

const GENERATED_PREFIX = "safety:";
const META_RULE_NAME = "safety:__config__";
const RUN_COMMANDS_DEFAULT_RULE_PREFIX = "safety:actions:run_commands:default:";
const INSTALL_DOWNLOAD_EXEC_PATTERNS = [
  "curl",
  "wget",
  "npm install",
  "pnpm add",
  "yarn add",
  "pip install",
  "apt-get install",
  "brew install",
];
const ACCESS_SECRETS_EXEC_PATTERNS = [
  ".env",
  "id_rsa",
  "/etc/shadow",
  "aws_secret_access_key",
  "token",
  "password",
  "secret",
];
const ACCESS_SECRETS_TOOL_NAMES = [
  "secrets_get",
  "secret_get",
  "credentials_get",
  "vault_read",
  "env_get",
];
const HTTPS_ONLY_TOOL_NAMES = [
  "web_fetch",
  "web_search",
  "browser",
  "navigate",
  "http",
  "exec",
  "bash",
  "gateway",
];

function unique(values: string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}

function parseCsv(raw: string): string[] {
  return unique(
    raw
      .split(/[,\n]/)
      .map((value) => value.trim())
      .filter(Boolean),
  );
}

type LegacyInternetMode = "allow_all" | "allow_list" | "block_list" | "block_all";

type LegacyInternetConfig = {
  mode?: LegacyInternetMode;
  allowedDomains?: string[];
  blockedDomains?: string[];
  warnedDomains?: string[];
  warnUnknownDomains?: boolean;
  blockDirectIpNavigation?: boolean;
  allowHttpsOnly?: boolean;
};

function normalizeWarnBehavior(value: unknown): InternetWarnBehavior {
  return value === "require_confirmation" || value === "alert" || value === "log_only"
    ? value
    : "log_only";
}

function legacyModeToDefaultAction(mode: unknown): InternetDefaultAction {
  return mode === "allow_list" || mode === "block_all" ? "block" : "allow";
}

function legacyInternetRules(input: LegacyInternetConfig): InternetRule[] {
  const mode = input.mode;
  const allowedDomains = unique((Array.isArray(input.allowedDomains) ? input.allowedDomains : []).map(normalizeInternetPattern)).filter(Boolean);
  const blockedDomains = unique((Array.isArray(input.blockedDomains) ? input.blockedDomains : []).map(normalizeInternetPattern)).filter(Boolean);
  const warnedDomains = unique((Array.isArray(input.warnedDomains) ? input.warnedDomains : []).map(normalizeInternetPattern)).filter(Boolean);
  const rules: InternetRule[] = [];
  const pushRule = (pattern: string, action: "allow" | "block" | "warn") => {
    rules.push({
      id: createInternetRuleId(),
      pattern,
      matchType: "subdomain",
      action,
      warnBehavior: action === "warn" ? "log_only" : undefined,
    });
  };
  const allowFirst = mode === "allow_list" || mode === "block_all";
  if (allowFirst) allowedDomains.forEach((domain) => pushRule(domain, "allow"));
  blockedDomains.forEach((domain) => pushRule(domain, "block"));
  warnedDomains.forEach((domain) => pushRule(domain, "warn"));
  if (!allowFirst) allowedDomains.forEach((domain) => pushRule(domain, "allow"));
  return rules;
}

function normalizeTernary(value: unknown): TernaryMode {
  return value === "allow" || value === "warn" || value === "block" ? value : "allow";
}

function normalizeConfig(input: SafetyConfig): SafetyConfig {
  const mode: SafetyMode =
    input.mode === "relaxed" || input.mode === "balanced" || input.mode === "strict"
      ? input.mode
      : "balanced";
  const legacyInternet = input.internet as unknown as LegacyInternetConfig;
  const internetRulesRaw = Array.isArray((input.internet as { rules?: unknown[] }).rules)
    ? ((input.internet as { rules?: unknown[] }).rules ?? [])
    : legacyInternetRules(legacyInternet);
  const defaultActionRaw = (input.internet as { defaultAction?: unknown }).defaultAction;
  const defaultAction: InternetDefaultAction =
    defaultActionRaw === "allow" || defaultActionRaw === "block"
      ? defaultActionRaw
      : legacyModeToDefaultAction(legacyInternet.mode);

  return {
    mode,
    actions: {
      runCommands: normalizeTernary(input.actions.runCommands),
      allowedCommands: unique((Array.isArray(input.actions.allowedCommands) ? input.actions.allowedCommands : []).map((v) => v.toLowerCase())),
      warnedCommands: unique((Array.isArray(input.actions.warnedCommands) ? input.actions.warnedCommands : []).map((v) => v.toLowerCase())),
      blockedCommands: unique((Array.isArray(input.actions.blockedCommands) ? input.actions.blockedCommands : []).map((v) => v.toLowerCase())),
      writeFiles: normalizeTernary(input.actions.writeFiles),
      installDownloads: normalizeTernary(input.actions.installDownloads),
      accessSecrets: normalizeTernary(input.actions.accessSecrets),
      payments: normalizeTernary(input.actions.payments),
    },
    internet: {
      defaultAction,
      rules: normalizeInternetRules(internetRulesRaw),
      warnUnknownDomains: Boolean((input.internet as { warnUnknownDomains?: boolean }).warnUnknownDomains),
      warnUnknownBehavior: normalizeWarnBehavior((input.internet as { warnUnknownBehavior?: unknown }).warnUnknownBehavior),
      blockDirectIpNavigation: Boolean((input.internet as { blockDirectIpNavigation?: boolean }).blockDirectIpNavigation),
      allowHttpsOnly: Boolean((input.internet as { allowHttpsOnly?: boolean }).allowHttpsOnly),
    },
    intentPolicy: input.intentPolicy,
  };
}

/**
 * Returns the baseline global safety configuration used on bootstrap/reset.
 */
export function defaultSafetyConfig(): SafetyConfig {
  return {
    mode: "balanced",
    actions: {
      runCommands: "block",
      allowedCommands: ["git", "npm", "pnpm", "python"],
      warnedCommands: [],
      blockedCommands: [],
      writeFiles: "warn",
      installDownloads: "block",
      accessSecrets: "block",
      payments: "block",
    },
    internet: {
      defaultAction: "allow",
      rules: [],
      warnUnknownDomains: false,
      warnUnknownBehavior: "log_only",
      blockDirectIpNavigation: true,
      allowHttpsOnly: true,
    },
    intentPolicy: {
      mode: "audit",
      llmEnabled: true,
      baselineModel: "gpt-4.1-mini",
      alignmentModel: "gpt-4.1-mini",
      outputModel: "gpt-4.1-mini",
      outputSanitization: true,
      driftWarnThreshold: 35,
      driftBlockThreshold: 70,
      ambiguousLowerBound: 30,
      ambiguousUpperBound: 60,
      signalWeights: {
        scopeMismatch: 1,
        domainOutOfBoundary: 18,
        unexpectedNetworkAccess: 20,
        llmMisaligned: 26,
        llmSuspicious: 8,
        llmAlignedRelief: 12,
        outputBase: 18,
        outputPerSignal: 6,
        outputSanitization: 0,
      },
      domainClasses: [
        {
          id: "finance",
          patterns: [
            "finance.yahoo.com",
            "marketwatch.com",
            "bloomberg.com",
            "ft.com",
            "wsj.com",
            "cnbc.com",
            "reuters.com",
          ],
        },
      ],
      normalizationRules: {
        localPathPrefixes: ["~/", "./", "../", "/", "/home/", "/tmp/", "/var/", "/etc/"],
        localFileExtensions: ["md", "txt", "json", "yaml", "yml", "csv", "log", "pdf", "doc", "docx"],
        ignoredDomainTokens: ["localhost", "event.params", "params", "payload", "content"],
      },
      toolScopeMappings: [],
      taskDefaults: [],
      alignmentReliefEnabled: true,
      alignmentReliefThreshold: 85,
      failMode: "fail_open",
    },
  };
}

/**
 * Builds preset safety profiles (`relaxed|balanced|strict`) from defaults.
 */
export function configFromMode(mode: SafetyMode): SafetyConfig {
  const base = defaultSafetyConfig();
  if (mode === "relaxed") {
    return {
      ...base,
      mode,
      actions: {
        ...base.actions,
        runCommands: "allow",
        allowedCommands: [],
        warnedCommands: [],
        blockedCommands: [],
        writeFiles: "allow",
        installDownloads: "warn",
        accessSecrets: "warn",
      },
      internet: {
        ...base.internet,
        defaultAction: "allow",
        rules: [],
        warnUnknownDomains: false,
        warnUnknownBehavior: "log_only",
        allowHttpsOnly: false,
      },
      intentPolicy: {
        ...base.intentPolicy,
        mode: "audit",
        llmEnabled: false,
      },
    };
  }
  if (mode === "strict") {
    return {
      ...base,
      mode,
      actions: {
        ...base.actions,
        runCommands: "block",
        allowedCommands: ["git", "npm", "pnpm"],
        warnedCommands: [],
        blockedCommands: [],
        writeFiles: "block",
        installDownloads: "block",
        accessSecrets: "block",
      },
      internet: {
        ...base.internet,
        defaultAction: "block",
        rules: [
          { id: createInternetRuleId(), pattern: "github.com", matchType: "subdomain", action: "allow" },
          { id: createInternetRuleId(), pattern: "api.github.com", matchType: "exact", action: "allow" },
          { id: createInternetRuleId(), pattern: "registry.npmjs.org", matchType: "subdomain", action: "allow" },
          { id: createInternetRuleId(), pattern: "pypi.org", matchType: "subdomain", action: "allow" },
          { id: createInternetRuleId(), pattern: "files.pythonhosted.org", matchType: "subdomain", action: "allow" },
        ],
        warnUnknownDomains: false,
        warnUnknownBehavior: "log_only",
        blockDirectIpNavigation: true,
        allowHttpsOnly: true,
      },
      intentPolicy: {
        ...base.intentPolicy,
        mode: "enforce",
        llmEnabled: true,
        failMode: "fail_closed",
        driftWarnThreshold: 28,
        driftBlockThreshold: 62,
      },
    };
  }
  return { ...base, mode: "balanced" };
}

type PolicyInsert = {
  name: string;
  scope: string;
  action: string;
  priority: number;
  enabled: boolean;
  toolName?: string | null;
  commandContains?: string | null;
  channelId?: string | null;
  toContains?: string | null;
  contentContains?: string | null;
  reason?: string | null;
};

function buildPolicyRows(cfg: SafetyConfig): PolicyInsert[] {
  const rows: PolicyInsert[] = [];
  const add = (row: PolicyInsert) => rows.push(row);

  cfg.actions.allowedCommands.forEach((cmd, index) => {
    add({
      name: `safety:actions:run_commands:allow:${cmd}`,
      scope: "tool",
      action: "allow",
      priority: 10 + index,
      enabled: true,
      toolName: "exec",
      commandContains: cmd,
      reason: "Safety run commands allow-list",
    });
  });

  cfg.actions.blockedCommands.forEach((cmd, index) => {
    add({
      name: `safety:actions:run_commands:block:${cmd}`,
      scope: "tool",
      action: "block",
      priority: 30 + index,
      enabled: true,
      toolName: "exec",
      commandContains: cmd,
      reason: "Safety run commands block-list",
    });
  });

  cfg.actions.warnedCommands.forEach((cmd, index) => {
    add({
      name: `safety:actions:run_commands:warn:${cmd}`,
      scope: "tool",
      action: "warn",
      priority: 50 + index,
      enabled: true,
      toolName: "exec",
      commandContains: cmd,
      reason: "Safety run commands warn-list",
    });
  });

  if (cfg.actions.runCommands !== "allow") {
    add({
      name: `${RUN_COMMANDS_DEFAULT_RULE_PREFIX}${cfg.actions.runCommands}`,
      scope: "tool",
      action: cfg.actions.runCommands,
      priority: 68,
      enabled: true,
      toolName: "exec",
      commandContains: null,
      reason:
        cfg.actions.runCommands === "block"
          ? "Safety run commands default blocks unmatched execution commands"
          : "Safety run commands default warns on unmatched execution commands",
    });
  }

  if (cfg.actions.installDownloads !== "allow") {
    add({
      name: `safety:actions:install_downloads:${cfg.actions.installDownloads}:tool:skill`,
      scope: "tool",
      action: cfg.actions.installDownloads,
      priority: 1,
      enabled: true,
      toolName: "skill",
      reason:
        cfg.actions.installDownloads === "block"
          ? "Safety actions policy blocks skill installs"
          : "Safety actions policy warns on skill installs",
    });
    INSTALL_DOWNLOAD_EXEC_PATTERNS.forEach((pattern, index) => {
      add({
        name: `safety:actions:install_downloads:${cfg.actions.installDownloads}:exec:${index + 1}`,
        scope: "tool",
        action: cfg.actions.installDownloads,
        priority: 2 + index,
        enabled: true,
        toolName: "exec",
        commandContains: pattern,
        reason:
          cfg.actions.installDownloads === "block"
            ? "Safety actions policy blocks download/install command patterns"
            : "Safety actions policy warns on download/install command patterns",
      });
    });
  }

  if (cfg.actions.accessSecrets !== "allow") {
    ACCESS_SECRETS_TOOL_NAMES.forEach((toolName, index) => {
      add({
        name: `safety:actions:access_secrets:${cfg.actions.accessSecrets}:tool:${toolName}`,
        scope: "tool",
        action: cfg.actions.accessSecrets,
        priority: 10 + index,
        enabled: true,
        toolName,
        reason:
          cfg.actions.accessSecrets === "block"
            ? "Safety actions policy blocks secret-access tools"
            : "Safety actions policy warns on secret-access tools",
      });
    });
    ACCESS_SECRETS_EXEC_PATTERNS.forEach((pattern, index) => {
      add({
        name: `safety:actions:access_secrets:${cfg.actions.accessSecrets}:exec:${index + 1}`,
        scope: "tool",
        action: cfg.actions.accessSecrets,
        priority: 20 + index,
        enabled: true,
        toolName: "exec",
        commandContains: pattern,
        reason:
          cfg.actions.accessSecrets === "block"
            ? "Safety actions policy blocks secret-access command patterns"
            : "Safety actions policy warns on secret-access command patterns",
      });
    });
  }

  if (cfg.actions.writeFiles !== "allow") {
    add({
      name: `safety:actions:write_files:${cfg.actions.writeFiles}`,
      scope: "tool",
      action: cfg.actions.writeFiles,
      priority: 44,
      enabled: true,
      toolName: "write",
      reason:
        cfg.actions.writeFiles === "block"
          ? "Safety actions policy blocks file writes"
          : "Safety actions policy warns on file writes",
    });
  }

  if (cfg.actions.payments !== "allow") {
    add({
      name: `safety:actions:payments:${cfg.actions.payments}`,
      scope: "tool",
      action: cfg.actions.payments,
      priority: 48,
      enabled: true,
      toolName: "payments_send",
      reason:
        cfg.actions.payments === "block"
          ? "Safety actions policy blocks payment actions"
          : "Safety actions policy warns on payment actions",
    });
  }

  cfg.internet.rules.forEach((rule, index) => {
    const pattern = normalizeInternetPattern(rule.pattern);
    if (!pattern) return;
    const action = rule.action === "allow" || rule.action === "warn" || rule.action === "block"
      ? rule.action
      : "allow";
    add({
      name: `safety:internet:rule:${index + 1}:${action}:${pattern}`,
      scope: "domain",
      action,
      priority: 120 + index,
      enabled: true,
      contentContains: serializeInternetRuleMatch(rule.matchType, pattern),
      reason:
        action === "warn"
          ? `Safety internet rule #${index + 1} warns (${rule.warnBehavior ?? "log_only"})`
          : `Safety internet rule #${index + 1}`,
    });
  });

  if (cfg.internet.allowHttpsOnly) {
    HTTPS_ONLY_TOOL_NAMES.forEach((toolName, index) => {
      add({
        name: `safety:internet:https_only:block:${toolName}`,
        scope: "tool",
        action: "block",
        priority: 80 + index,
        enabled: true,
        toolName,
        commandContains: "http://",
        reason: "Safety internet policy blocks insecure http targets",
      });
    });
  }

  if (cfg.internet.blockDirectIpNavigation) {
    add({
      name: "safety:internet:block_direct_ip",
      scope: "ip",
      action: "block",
      priority: 880,
      enabled: true,
      contentContains: null,
      reason: "Safety internet policy blocks direct IP navigation",
    });
  }

  if (cfg.internet.defaultAction === "block") {
    add({
      name: "safety:internet:default_block_domains",
      scope: "domain",
      action: "block",
      priority: 900,
      enabled: true,
      contentContains: null,
      reason: "Safety internet default policy blocks unmatched domains",
    });
    add({
      name: "safety:internet:default_block_ips",
      scope: "ip",
      action: "block",
      priority: 901,
      enabled: true,
      contentContains: null,
      reason: "Safety internet default policy blocks unmatched IP targets",
    });
  } else if (cfg.internet.warnUnknownDomains) {
    add({
      name: "safety:internet:warn_unknown_domains",
      scope: "domain",
      action: "warn",
      priority: 900,
      enabled: true,
      contentContains: null,
      reason: `Safety internet warns on unmatched domains (${cfg.internet.warnUnknownBehavior})`,
    });
    add({
      name: "safety:internet:warn_unknown_ips",
      scope: "ip",
      action: "warn",
      priority: 901,
      enabled: true,
      contentContains: null,
      reason: `Safety internet warns on unmatched IP targets (${cfg.internet.warnUnknownBehavior})`,
    });
  }

  return rows;
}

/**
 * Loads persisted global safety config plus global intent policy overlay.
 */
export async function loadSafetyConfig(): Promise<SafetyConfig> {
  const fallback = defaultSafetyConfig();
  const [meta, intentPolicy] = await Promise.all([
    prisma.policyRule.findFirst({
      where: { name: META_RULE_NAME },
      orderBy: { updatedAt: "desc" },
      select: { reason: true },
    }),
    loadIntentPolicyConfig({ scopeLevel: "global" }),
  ]);

  let parsed: SafetyConfig | null = null;
  if (meta?.reason) {
    try {
      parsed = JSON.parse(meta.reason) as SafetyConfig;
    } catch {
      parsed = null;
    }
  }
  const cfg = normalizeConfig(parsed ?? fallback);
  cfg.intentPolicy = intentPolicy;
  return cfg;
}

/**
 * Applies safety configuration by regenerating policy-rule rows transactionally.
 */
export async function applySafetyConfig(input: SafetyConfig): Promise<SafetyConfig> {
  const cfg = normalizeConfig(input);
  const policyRows = buildPolicyRows(cfg);

  await prisma.$transaction(async (tx) => {
    await tx.policyRule.deleteMany({ where: { name: { startsWith: GENERATED_PREFIX } } });
    await tx.policyRule.create({
      data: {
        name: META_RULE_NAME,
        scope: "tool",
        action: "allow",
        priority: 9999,
        enabled: false,
        reason: JSON.stringify({
          mode: cfg.mode,
          actions: cfg.actions,
          internet: cfg.internet,
        }),
      },
    });

    if (policyRows.length > 0) {
      await tx.policyRule.createMany({
        data: policyRows.map((row) => ({
          name: row.name,
          scope: row.scope,
          action: row.action,
          priority: row.priority,
          enabled: row.enabled,
          toolName: row.toolName ?? null,
          commandContains: row.commandContains ?? null,
          channelId: row.channelId ?? null,
          toContains: row.toContains ?? null,
          contentContains: row.contentContains ?? null,
          reason: row.reason ?? null,
        })),
      });
    }
  });

  await saveIntentPolicyConfig(cfg.intentPolicy, { scopeLevel: "global" });
  return cfg;
}

/**
 * Parses comma/newline-separated token lists used in safety form inputs.
 */
export function parseCsvInput(raw: string): string[] {
  return parseCsv(raw);
}
