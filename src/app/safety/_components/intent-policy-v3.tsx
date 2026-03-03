/**
 * @fileoverview ClawSight SIEM module: platform/src/app/safety/_components/intent-policy-v3.tsx.
 */
"use client";

import { useEffect, useMemo, useState } from "react";
import { cn } from "@/lib/utils";
import {
  ShieldOff,
  Eye,
  ShieldCheck,
  SlidersHorizontal,
  Eraser,
  Brain,
  ChevronDown,
  Save,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";

type IntentMode = "off" | "audit" | "enforce";
type BaselineMethod = "heuristic" | "model";

type IntentPolicyConfig = {
  mode: IntentMode;
  llmEnabled: boolean;
  outputSanitizationEnabled: boolean;
  thresholds: {
    warn: number;
    block: number;
    ambiguousLower: number;
    ambiguousUpper: number;
  };
  failMode: "fail_open" | "fail_closed";
  models: {
    baseline: string;
    alignment: string;
    output: string;
  };
};

type IntentPolicyImpact = {
  window: "24h";
  executionsEvaluated: number;
  decisionsWarn: number;
  decisionsBlock: number;
  outputsSanitized: number;
  llmCallsBaseline?: number;
  llmCallsAlignment?: number;
  llmCallsOutput?: number;
  llmTokensInput?: number;
  llmTokensOutput?: number;
  llmTokensTotal?: number;
};

type UiPolicy = {
  mode: IntentMode;
  warnThreshold: number;
  blockThreshold: number;
  sanitizeOutput: boolean;
  failBehavior: "fail_open" | "fail_closed";
  baselineMethod: BaselineMethod;
  alignmentModel: string;
  outputModel: string;
  llmEnabled: boolean;
};

const DEFAULT_UI_POLICY: UiPolicy = {
  mode: "audit",
  warnThreshold: 35,
  blockThreshold: 70,
  sanitizeOutput: true,
  failBehavior: "fail_open",
  baselineMethod: "model",
  alignmentModel: "gpt-4.1-mini",
  outputModel: "gpt-4.1-mini",
  llmEnabled: true,
};

const modeOptions: { value: IntentMode; label: string; icon: typeof ShieldOff; description: string }[] = [
  {
    value: "off",
    label: "Off",
    icon: ShieldOff,
    description: "Intent policy is disabled. No baselines, drift tracking, or decisions.",
  },
  {
    value: "audit",
    label: "Audit",
    icon: Eye,
    description: "Record drift and decisions; don't block. Good for initial rollout.",
  },
  {
    value: "enforce",
    label: "Enforce",
    icon: ShieldCheck,
    description: "Block tool calls that violate intent policy. Production-ready.",
  },
];

function mapConfigToUi(config: Partial<IntentPolicyConfig>): UiPolicy {
  const warn = Number(config.thresholds?.warn ?? 35);
  const block = Number(config.thresholds?.block ?? 70);
  const baselineModel = String(config.models?.baseline || "gpt-4.1-mini");
  const baselineMethod: BaselineMethod =
    !config.llmEnabled || baselineModel.toLowerCase() === "heuristic" ? "heuristic" : "model";
  return {
    mode: config.mode === "off" || config.mode === "enforce" || config.mode === "audit" ? config.mode : "audit",
    warnThreshold: Number.isFinite(warn) ? Math.max(5, Math.min(95, Math.round(warn))) : 35,
    blockThreshold: Number.isFinite(block) ? Math.max(10, Math.min(100, Math.round(block))) : 70,
    sanitizeOutput: Boolean(config.outputSanitizationEnabled ?? true),
    failBehavior: config.failMode === "fail_closed" ? "fail_closed" : "fail_open",
    baselineMethod,
    alignmentModel: String(config.models?.alignment || "gpt-4.1-mini"),
    outputModel: String(config.models?.output || "gpt-4.1-mini"),
    llmEnabled: Boolean(config.llmEnabled ?? true),
  };
}

function mapUiToPayload(ui: UiPolicy, previous: IntentPolicyConfig | null) {
  const next = {
    mode: ui.mode,
    llmEnabled: ui.llmEnabled,
    outputSanitizationEnabled: ui.sanitizeOutput,
    thresholds: {
      warn: ui.warnThreshold,
      block: ui.blockThreshold,
      ambiguousLower:
        previous?.thresholds?.ambiguousLower ??
        Math.max(0, Math.min(100, ui.warnThreshold - 5)),
      ambiguousUpper:
        previous?.thresholds?.ambiguousUpper ??
        Math.max(1, Math.min(100, ui.blockThreshold - 5)),
    },
    failMode: ui.failBehavior,
    models: {
      baseline:
        ui.baselineMethod === "heuristic"
          ? "heuristic"
          : previous?.models?.baseline && previous.models.baseline !== "heuristic"
            ? previous.models.baseline
            : "gpt-4.1-mini",
      alignment: ui.alignmentModel,
      output: ui.outputModel,
    },
  };
  return next;
}

function ThresholdVisual({ warn, block }: { warn: number; block: number }) {
  return (
    <div className="flex flex-col gap-1.5">
      <div className="relative h-2.5 w-full overflow-hidden rounded-full bg-secondary">
        <div
          className="absolute left-0 top-0 h-full rounded-l-full bg-emerald-500/30"
          style={{ width: `${warn}%` }}
        />
        <div
          className="absolute top-0 h-full bg-yellow-500/30"
          style={{ left: `${warn}%`, width: `${Math.max(0, block - warn)}%` }}
        />
        <div
          className="absolute top-0 h-full rounded-r-full bg-red-500/30"
          style={{ left: `${block}%`, width: `${Math.max(0, 100 - block)}%` }}
        />
        <div className="absolute top-0 h-full w-0.5 bg-yellow-500" style={{ left: `${warn}%` }} />
        <div className="absolute top-0 h-full w-0.5 bg-red-500" style={{ left: `${block}%` }} />
      </div>
      <div className="flex justify-between text-[10px] text-muted-foreground">
        <span>0 — Normal</span>
        <span className="text-yellow-500">Warn ({warn})</span>
        <span className="text-muted-foreground">Ambiguous</span>
        <span className="text-red-500">Block ({block})</span>
        <span>100</span>
      </div>
    </div>
  );
}

export default function IntentPolicyV3() {
  const [policy, setPolicy] = useState<UiPolicy>(DEFAULT_UI_POLICY);
  const [savedPolicy, setSavedPolicy] = useState<UiPolicy>(DEFAULT_UI_POLICY);
  const [rawConfig, setRawConfig] = useState<IntentPolicyConfig | null>(null);
  const [impact, setImpact] = useState<IntentPolicyImpact | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [advancedOpen, setAdvancedOpen] = useState(false);

  const dirty = useMemo(
    () => JSON.stringify(policy) !== JSON.stringify(savedPolicy),
    [policy, savedPolicy],
  );

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      setError(null);
      try {
        const [response, impactResponse] = await Promise.all([
          fetch("/api/safety/intent-policy", { cache: "no-store" }),
          fetch("/api/safety/intent-policy/impact?window=24h", { cache: "no-store" }),
        ]);
        const json = (await response.json()) as {
          ok?: boolean;
          config?: IntentPolicyConfig;
          error?: string;
        };
        if (!response.ok || !json.config) {
          throw new Error(json.error || "Failed to load intent policy");
        }
        const impactJson = (await impactResponse.json()) as {
          ok?: boolean;
          impact?: IntentPolicyImpact;
        };
        if (cancelled) return;
        const mapped = mapConfigToUi(json.config);
        setRawConfig(json.config);
        setPolicy(mapped);
        setSavedPolicy(mapped);
        setImpact(impactResponse.ok && impactJson.impact ? impactJson.impact : null);
      } catch (err) {
        if (!cancelled) setError(String(err));
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  async function savePolicy() {
    setSaving(true);
    setError(null);
    try {
      const payload = mapUiToPayload(policy, rawConfig);
      const response = await fetch("/api/safety/intent-policy", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      const json = (await response.json()) as {
        ok?: boolean;
        config?: IntentPolicyConfig;
        error?: string;
      };
      if (!response.ok || !json.config) {
        throw new Error(json.error || "Failed to save intent policy");
      }
      const mapped = mapConfigToUi(json.config);
      setRawConfig(json.config);
      setPolicy(mapped);
      setSavedPolicy(mapped);
    } catch (err) {
      setError(String(err));
    } finally {
      setSaving(false);
    }
  }

  function resetPolicy() {
    setPolicy(savedPolicy);
    setError(null);
  }

  const numberFormatter = useMemo(() => new Intl.NumberFormat("en-US"), []);
  const totalIntentLlmTokens = Number(impact?.llmTokensTotal ?? 0);

  if (loading) {
    return (
      <Card className="border-border">
        <CardContent className="p-5 text-sm text-muted-foreground">
          Loading intent policy...
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="flex flex-col gap-5">
      <p className="text-xs text-muted-foreground">
        Intent policy tracks what each execution was supposed to do (baseline), how far it drifted, and what decisions were made at each tool boundary.
      </p>

      {error ? (
        <div className="rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs text-red-200">
          {error}
        </div>
      ) : null}

      <Card className="border-border">
        <CardContent className="p-4 text-xs text-muted-foreground">
          Last 24h: Evaluated{" "}
          <span className="font-semibold text-foreground">{numberFormatter.format(Number(impact?.executionsEvaluated ?? 0))}</span>
          {" · "}Warned{" "}
          <span className="font-semibold text-amber-300">{numberFormatter.format(Number(impact?.decisionsWarn ?? 0))}</span>
          {" · "}Blocked{" "}
          <span className="font-semibold text-red-300">{numberFormatter.format(Number(impact?.decisionsBlock ?? 0))}</span>
          {" · "}Sanitized{" "}
          <span className="font-semibold text-teal-300">{numberFormatter.format(Number(impact?.outputsSanitized ?? 0))}</span>
          {" · "}LLM intent tokens{" "}
          <span className="font-semibold text-foreground">{numberFormatter.format(totalIntentLlmTokens)}</span>
        </CardContent>
      </Card>

      <Card className="border-border">
        <CardContent className="p-5">
          <h3 className="mb-3 text-sm font-medium text-foreground">Mode</h3>
          <div className="flex flex-col gap-2">
            {modeOptions.map((opt) => (
              <button
                key={opt.value}
                onClick={() => setPolicy((prev) => ({ ...prev, mode: opt.value }))}
                className={cn(
                  "flex items-start gap-3 rounded-lg border px-4 py-3 text-left transition-colors",
                  policy.mode === opt.value
                    ? "border-primary bg-primary/5"
                    : "border-border bg-secondary hover:bg-accent",
                )}
              >
                <div
                  className={cn(
                    "mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full border-2",
                    policy.mode === opt.value ? "border-primary" : "border-muted-foreground",
                  )}
                >
                  {policy.mode === opt.value ? <div className="h-2 w-2 rounded-full bg-primary" /> : null}
                </div>
                <div className="flex items-center gap-2">
                  <opt.icon
                    className={cn(
                      "h-4 w-4 shrink-0",
                      policy.mode === opt.value ? "text-primary" : "text-muted-foreground",
                    )}
                  />
                  <div>
                    <span
                      className={cn(
                        "text-sm font-medium",
                        policy.mode === opt.value ? "text-foreground" : "text-secondary-foreground",
                      )}
                    >
                      {opt.label}
                    </span>
                    {opt.value === "enforce" ? (
                      <span className="ml-2 rounded bg-primary/10 px-1.5 py-0.5 text-[10px] font-medium text-primary">
                        Production
                      </span>
                    ) : null}
                    <p className="mt-0.5 text-xs text-muted-foreground">{opt.description}</p>
                  </div>
                </div>
              </button>
            ))}
          </div>
        </CardContent>
      </Card>

      <Card className="border-border">
        <CardContent className="p-5">
          <div className="mb-3 flex items-center gap-2">
            <SlidersHorizontal className="h-4 w-4 text-muted-foreground" />
            <h3 className="text-sm font-medium text-foreground">Drift Thresholds</h3>
          </div>
          <div className="flex flex-col gap-4">
            <div className="flex items-center gap-6">
              <div>
                <label className="mb-1 block text-xs font-medium text-muted-foreground">Warn at</label>
                <div className="flex items-center gap-2">
                  <input
                    type="range"
                    min={5}
                    max={95}
                    value={policy.warnThreshold}
                    onChange={(e) => {
                      const val = parseInt(e.target.value, 10);
                      setPolicy((prev) => ({
                        ...prev,
                        warnThreshold: Math.min(val, prev.blockThreshold - 5),
                      }));
                    }}
                    className="w-32 accent-yellow-500"
                  />
                  <span className="w-8 text-right font-mono text-sm text-yellow-500">{policy.warnThreshold}</span>
                </div>
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium text-muted-foreground">Block at</label>
                <div className="flex items-center gap-2">
                  <input
                    type="range"
                    min={10}
                    max={100}
                    value={policy.blockThreshold}
                    onChange={(e) => {
                      const val = parseInt(e.target.value, 10);
                      setPolicy((prev) => ({
                        ...prev,
                        blockThreshold: Math.max(val, prev.warnThreshold + 5),
                      }));
                    }}
                    className="w-32 accent-red-500"
                  />
                  <span className="w-8 text-right font-mono text-sm text-red-500">{policy.blockThreshold}</span>
                </div>
              </div>
            </div>
            <ThresholdVisual warn={policy.warnThreshold} block={policy.blockThreshold} />
          </div>
        </CardContent>
      </Card>

      <Card className="border-border">
        <CardContent className="p-5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Eraser className="h-4 w-4 text-muted-foreground" />
              <div>
                <h3 className="text-sm font-medium text-foreground">Output Sanitization</h3>
                <p className="text-xs text-muted-foreground">
                  Sanitize untrusted tool output before it enters context
                </p>
              </div>
            </div>
            <button
              type="button"
              className={cn(
                "flex h-5 w-9 shrink-0 items-center rounded-full px-0.5 transition-colors",
                policy.sanitizeOutput ? "bg-primary" : "bg-muted",
              )}
              onClick={() => setPolicy((prev) => ({ ...prev, sanitizeOutput: !prev.sanitizeOutput }))}
            >
              <span
                className={cn(
                  "h-4 w-4 rounded-full transition-transform",
                  policy.sanitizeOutput
                    ? "translate-x-4 bg-primary-foreground"
                    : "translate-x-0 bg-muted-foreground",
                )}
              />
            </button>
          </div>
          {policy.sanitizeOutput ? (
            <div className="mt-3 flex flex-wrap gap-1.5">
              {["Instruction-like payloads", "Delimiters", "Base64 blocks", "Credential patterns"].map((p) => (
                <span key={p} className="rounded bg-secondary px-2 py-0.5 text-[10px] text-muted-foreground">
                  {p}
                </span>
              ))}
            </div>
          ) : null}
        </CardContent>
      </Card>

      <Card className="border-border">
        <CardContent className="p-0">
          <button
            onClick={() => setAdvancedOpen((prev) => !prev)}
            className="flex w-full items-center justify-between px-5 py-4 text-left"
          >
            <div className="flex items-center gap-2">
              <Brain className="h-4 w-4 text-muted-foreground" />
              <h3 className="text-sm font-medium text-foreground">Advanced</h3>
              <span className="text-xs text-muted-foreground">Models & fail behavior</span>
            </div>
            <ChevronDown
              className={cn(
                "h-4 w-4 text-muted-foreground transition-transform",
                advancedOpen ? "rotate-180" : "",
              )}
            />
          </button>
          {advancedOpen ? (
            <div className="border-t border-border px-5 py-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="mb-1 block text-xs font-medium text-muted-foreground">Baseline method</label>
                  <select
                    value={policy.baselineMethod}
                    onChange={(e) =>
                      setPolicy((prev) => ({
                        ...prev,
                        baselineMethod: e.target.value === "heuristic" ? "heuristic" : "model",
                      }))
                    }
                    className="w-full rounded-md border border-border bg-secondary px-3 py-1.5 text-xs text-foreground"
                  >
                    <option value="heuristic">Heuristic</option>
                    <option value="model">LLM-based</option>
                  </select>
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium text-muted-foreground">Fail behavior</label>
                  <select
                    value={policy.failBehavior}
                    onChange={(e) =>
                      setPolicy((prev) => ({
                        ...prev,
                        failBehavior: e.target.value === "fail_closed" ? "fail_closed" : "fail_open",
                      }))
                    }
                    className="w-full rounded-md border border-border bg-secondary px-3 py-1.5 text-xs text-foreground"
                  >
                    <option value="fail_closed">Fail closed (safer)</option>
                    <option value="fail_open">Fail open</option>
                  </select>
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium text-muted-foreground">Alignment model</label>
                  <Input
                    value={policy.alignmentModel}
                    onChange={(e) =>
                      setPolicy((prev) => ({ ...prev, alignmentModel: e.target.value }))
                    }
                    className="h-[31px] text-xs"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium text-muted-foreground">Output model</label>
                  <Input
                    value={policy.outputModel}
                    onChange={(e) =>
                      setPolicy((prev) => ({ ...prev, outputModel: e.target.value }))
                    }
                    className="h-[31px] text-xs"
                  />
                </div>
              </div>
              <div className="mt-4 flex items-center justify-between rounded-md border border-border bg-secondary px-4 py-2.5">
                <div>
                  <span className="text-sm font-medium text-foreground">LLM-powered analysis</span>
                  <p className="text-xs text-muted-foreground">
                    Use AI models for advanced intent classification
                  </p>
                </div>
                <button
                  type="button"
                  className={cn(
                    "flex h-5 w-9 shrink-0 items-center rounded-full px-0.5 transition-colors",
                    policy.llmEnabled ? "bg-primary" : "bg-muted",
                  )}
                  onClick={() => setPolicy((prev) => ({ ...prev, llmEnabled: !prev.llmEnabled }))}
                >
                  <span
                    className={cn(
                      "h-4 w-4 rounded-full transition-transform",
                      policy.llmEnabled
                        ? "translate-x-4 bg-primary-foreground"
                        : "translate-x-0 bg-muted-foreground",
                    )}
                  />
                </button>
              </div>
            </div>
          ) : null}
        </CardContent>
      </Card>

      <Card className="border-border">
        <CardContent className="flex items-center justify-end gap-2 p-4">
          <Button variant="outline" onClick={resetPolicy} disabled={!dirty || saving}>
            Reset
          </Button>
          <Button onClick={savePolicy} disabled={!dirty || saving}>
            <Save className="mr-1.5 h-3.5 w-3.5" />
            {saving ? "Saving..." : "Save Intent Policy"}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
