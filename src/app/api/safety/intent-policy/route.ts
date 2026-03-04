/**
 * @fileoverview ClawSight SIEM module: platform/src/app/api/safety/intent-policy/route.ts.
 */
import { NextResponse } from "next/server";
import { authorizeAdminRequest } from "@/lib/auth";
import { applySafetyConfig, loadSafetyConfig } from "@/lib/safety-config";

type UiIntentPolicyConfig = {
  mode: "off" | "audit" | "enforce";
  llmEnabled: boolean;
  outputSanitizationEnabled: boolean;
  driftAddOnSanitize: boolean;
  sanitizeDriftWeight?: number;
  thresholds: {
    warn: number;
    block: number;
    ambiguousLower: number;
    ambiguousUpper: number;
  };
  strictnessPreset?: "relaxed" | "balanced" | "strict" | "custom";
  failMode: "fail_open" | "fail_closed";
  failModeEnforced: boolean;
  models: {
    baseline: string;
    alignment: string;
    output: string;
  };
  alignmentReliefEnabled: boolean;
  alignmentReliefThreshold: number;
  signalWeights: {
    scopeMismatch: number;
    domainOutOfBoundary: number;
    outputInjection: number;
    llmAlignmentAdjustment: number;
    localFileMisclassified: number;
    repetitionLoop?: number;
  };
  mappings: {
    toolScopes: Array<{ tool: string; scopes: string[] }>;
    domainClasses: Array<{ tag: string; patterns: string[] }>;
    localResourceRules: Array<{ name: string; enabled: boolean; pattern: string }>;
  };
};

function clampInt(value: unknown, fallback: number, min = 0, max = 100): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(min, Math.min(max, Math.round(parsed)));
}

function deriveStrictnessPreset(warn: number, block: number): "relaxed" | "balanced" | "strict" | "custom" {
  if (warn >= 45 && block >= 78) return "relaxed";
  if (warn <= 30 && block <= 65) return "strict";
  if (warn >= 31 && warn <= 44 && block >= 66 && block <= 77) return "balanced";
  return "custom";
}

function toUiConfig(input: Awaited<ReturnType<typeof loadSafetyConfig>>["intentPolicy"]): UiIntentPolicyConfig {
  const localResourceRules: Array<{ name: string; enabled: boolean; pattern: string }> = [];
  input.normalizationRules.localPathPrefixes.forEach((pattern, index) => {
    localResourceRules.push({
      name: `path_prefix_${index + 1}`,
      enabled: true,
      pattern,
    });
  });
  input.normalizationRules.localFileExtensions.forEach((ext, index) => {
    localResourceRules.push({
      name: `file_ext_${index + 1}`,
      enabled: true,
      pattern: `*.${ext}`,
    });
  });

  if (localResourceRules.length === 0) {
    localResourceRules.push({ name: "path_prefix_1", enabled: true, pattern: "~/" });
    localResourceRules.push({ name: "path_prefix_2", enabled: true, pattern: "/" });
    localResourceRules.push({ name: "file_ext_1", enabled: true, pattern: "*.md" });
  }

  return {
    mode: input.mode,
    llmEnabled: input.llmEnabled,
    outputSanitizationEnabled: input.outputSanitization,
    driftAddOnSanitize: input.signalWeights.outputSanitization > 0,
    sanitizeDriftWeight: input.signalWeights.outputSanitization,
    thresholds: {
      warn: input.driftWarnThreshold,
      block: input.driftBlockThreshold,
      ambiguousLower: input.ambiguousLowerBound,
      ambiguousUpper: input.ambiguousUpperBound,
    },
    strictnessPreset: deriveStrictnessPreset(input.driftWarnThreshold, input.driftBlockThreshold),
    failMode: input.failMode,
    failModeEnforced: false,
    models: {
      baseline: input.baselineModel,
      alignment: input.alignmentModel,
      output: input.outputModel,
    },
    alignmentReliefEnabled: Boolean(input.alignmentReliefEnabled),
    alignmentReliefThreshold: Number.isFinite(Number(input.alignmentReliefThreshold))
      ? Math.max(0, Math.min(100, Math.round(Number(input.alignmentReliefThreshold))))
      : 85,
    signalWeights: {
      scopeMismatch: input.signalWeights.scopeMismatch,
      domainOutOfBoundary: input.signalWeights.domainOutOfBoundary,
      outputInjection: input.signalWeights.outputPerSignal,
      llmAlignmentAdjustment: -Math.abs(input.signalWeights.llmAlignedRelief),
      localFileMisclassified: input.signalWeights.unexpectedNetworkAccess,
      repetitionLoop: 0,
    },
    mappings: {
      toolScopes: input.toolScopeMappings.map((item) => ({ tool: item.toolPattern, scopes: item.scopes })),
      domainClasses: input.domainClasses.map((item) => ({ tag: item.id, patterns: item.patterns })),
      localResourceRules,
    },
  };
}

function toIntentPolicyPatch(body: Partial<UiIntentPolicyConfig>, current: Awaited<ReturnType<typeof loadSafetyConfig>>["intentPolicy"]) {
  const next = { ...current };
  if (body.mode === "off" || body.mode === "audit" || body.mode === "enforce") {
    next.mode = body.mode;
  }
  if (typeof body.llmEnabled === "boolean") {
    next.llmEnabled = body.llmEnabled;
  }
  if (typeof body.outputSanitizationEnabled === "boolean") {
    next.outputSanitization = body.outputSanitizationEnabled;
  }
  if (body.models) {
    next.baselineModel = String(body.models.baseline || next.baselineModel);
    next.alignmentModel = String(body.models.alignment || next.alignmentModel);
    next.outputModel = String(body.models.output || next.outputModel);
  }
  if (typeof body.alignmentReliefEnabled === "boolean") {
    next.alignmentReliefEnabled = body.alignmentReliefEnabled;
  }
  if (typeof body.alignmentReliefThreshold === "number" && Number.isFinite(body.alignmentReliefThreshold)) {
    next.alignmentReliefThreshold = Math.max(0, Math.min(100, Math.round(body.alignmentReliefThreshold)));
  }
  if (body.thresholds) {
    next.driftWarnThreshold = clampInt(body.thresholds.warn, next.driftWarnThreshold, 0, 100);
    next.driftBlockThreshold = clampInt(body.thresholds.block, next.driftBlockThreshold, 0, 100);
    next.ambiguousLowerBound = clampInt(body.thresholds.ambiguousLower, next.ambiguousLowerBound, 0, 100);
    next.ambiguousUpperBound = clampInt(body.thresholds.ambiguousUpper, next.ambiguousUpperBound, 0, 100);
  }
  if (body.failMode === "fail_open" || body.failMode === "fail_closed") {
    next.failMode = body.failMode;
  }
  if (body.signalWeights) {
    next.signalWeights = {
      ...next.signalWeights,
      scopeMismatch: clampInt(body.signalWeights.scopeMismatch, next.signalWeights.scopeMismatch, 0, 30),
      domainOutOfBoundary: clampInt(body.signalWeights.domainOutOfBoundary, next.signalWeights.domainOutOfBoundary, 0, 40),
      unexpectedNetworkAccess: clampInt(body.signalWeights.localFileMisclassified, next.signalWeights.unexpectedNetworkAccess, 0, 40),
      outputPerSignal: clampInt(body.signalWeights.outputInjection, next.signalWeights.outputPerSignal, 0, 30),
      llmAlignedRelief: clampInt(Math.abs(body.signalWeights.llmAlignmentAdjustment), next.signalWeights.llmAlignedRelief, 0, 30),
    };
  }
  if (typeof body.driftAddOnSanitize === "boolean") {
    next.signalWeights.outputSanitization = body.driftAddOnSanitize
      ? clampInt(body.sanitizeDriftWeight, next.signalWeights.outputSanitization || 6, 0, 30)
      : 0;
  }
  if (body.mappings?.toolScopes) {
    next.toolScopeMappings = body.mappings.toolScopes
      .map((item) => ({
        toolPattern: String(item.tool || "").trim().toLowerCase(),
        scopes: (Array.isArray(item.scopes) ? item.scopes : [])
          .map((scope) => String(scope || "").trim().toLowerCase())
          .filter(Boolean) as Array<
            | "filesystem_read"
            | "filesystem_write"
            | "network_read"
            | "network_write"
            | "execution"
            | "messaging"
            | "credentials_access"
            | "payment"
            | "skill_install"
            | "scheduler"
          >,
      }))
      .filter((item) => item.toolPattern && item.scopes.length > 0);
  }
  if (body.mappings?.domainClasses) {
    next.domainClasses = body.mappings.domainClasses
      .map((item) => ({
        id: String(item.tag || "").trim().toLowerCase(),
        patterns: (Array.isArray(item.patterns) ? item.patterns : [])
          .map((pattern) => String(pattern || "").trim().toLowerCase())
          .filter(Boolean),
      }))
      .filter((item) => item.id && item.patterns.length > 0);
  }
  if (body.mappings?.localResourceRules) {
    const rules = body.mappings.localResourceRules.filter((item) => item.enabled);
    next.normalizationRules = {
      ...next.normalizationRules,
      localPathPrefixes: rules
        .map((item) => item.pattern)
        .filter((pattern) => /\/$|^\~\//.test(pattern) || pattern.startsWith("/")),
      localFileExtensions: rules
        .map((item) => item.pattern.match(/^\*?\.([a-z0-9]+)$/i)?.[1]?.toLowerCase() || "")
        .filter(Boolean),
      ignoredDomainTokens: next.normalizationRules.ignoredDomainTokens,
    };
  }
  next.alignmentReliefEnabled = next.alignmentReliefEnabled && Number(next.signalWeights.llmAlignedRelief) > 0;
  return next;
}

/**
 * Returns intent policy config projected into the v3 safety UI shape.
 */
export async function GET(request: Request) {
  try {
    const unauthorized = authorizeAdminRequest(request);
    if (unauthorized) return unauthorized;
    const config = await loadSafetyConfig();
    const llmKeyConfigured = Boolean(
      process.env.OPENAI_API_KEY ||
      process.env.OPENAI_KEY ||
      process.env.OPENROUTER_API_KEY,
    );
    return NextResponse.json({
      ok: true,
      config: toUiConfig(config.intentPolicy),
      llmKeyConfigured,
    });
  } catch (err) {
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}

/**
 * Applies intent policy patch payload from safety UI and persists via safety config.
 */
export async function POST(request: Request) {
  try {
    const unauthorized = authorizeAdminRequest(request);
    if (unauthorized) return unauthorized;
    const body = (await request.json()) as Partial<UiIntentPolicyConfig>;
    const current = await loadSafetyConfig();
    const nextIntent = toIntentPolicyPatch(body, current.intentPolicy);
    const saved = await applySafetyConfig({ ...current, intentPolicy: nextIntent });
    return NextResponse.json({ ok: true, config: toUiConfig(saved.intentPolicy) });
  } catch (err) {
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}
