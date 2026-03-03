/**
 * @fileoverview ClawSight SIEM module: platform/src/components/internet-policy-editor.tsx.
 */
"use client";

import { useMemo, useState } from "react";
import { ArrowDown, ArrowUp, Plus, Trash2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  createInternetRuleId,
  domainMatchesInternetRule,
  normalizeInternetPattern,
  normalizeInternetRules,
  type InternetDefaultAction,
  type InternetRule,
  type InternetRuleAction,
  type InternetRuleMatchType,
  type InternetWarnBehavior,
} from "@/lib/internet-policy";
import { cn } from "@/lib/utils";

type InternetPolicyEditorProps = {
  defaultAction: InternetDefaultAction;
  rules: InternetRule[];
  warnUnknownDomains: boolean;
  warnUnknownBehavior: InternetWarnBehavior;
  blockDirectIpNavigation: boolean;
  allowHttpsOnly: boolean;
};

type RuleConflict = {
  ruleIndex: number;
  shadowedByIndex: number;
  kind: "unreachable" | "redundant";
  message: string;
};

function sampleDomainsForRule(rule: InternetRule): string[] {
  const pattern = normalizeInternetPattern(rule.pattern);
  if (!pattern) return [];
  if (rule.matchType === "exact") return [pattern];
  if (rule.matchType === "subdomain") return [pattern, `probe.${pattern}`];
  const wildcardSampleOne = pattern.replace(/\*/g, "probe");
  const wildcardSampleTwo = pattern.replace(/\*/g, "deep.probe");
  return [wildcardSampleOne, wildcardSampleTwo].filter((sample, index, all) => {
    if (!sample) return false;
    if (all.indexOf(sample) !== index) return false;
    return domainMatchesInternetRule(sample, rule);
  });
}

function ruleCovers(previous: InternetRule, current: InternetRule): boolean {
  const samples = sampleDomainsForRule(current);
  if (samples.length === 0) return false;
  return samples.every((sample) => domainMatchesInternetRule(sample, previous));
}

function detectConflicts(rules: InternetRule[]): RuleConflict[] {
  const conflicts: RuleConflict[] = [];
  for (let index = 0; index < rules.length; index += 1) {
    const current = rules[index];
    const samples = sampleDomainsForRule(current);
    if (samples.length === 0) continue;
    for (let previous = 0; previous < index; previous += 1) {
      const maybeShadow = rules[previous];
      const isShadowed = ruleCovers(maybeShadow, current);
      if (!isShadowed) continue;
      const kind = maybeShadow.action === current.action ? "redundant" : "unreachable";
      conflicts.push({
        ruleIndex: index,
        shadowedByIndex: previous,
        kind,
        message:
          kind === "unreachable"
            ? `This rule will never match before rule #${previous + 1} (${maybeShadow.action}).`
            : `This rule is fully covered by rule #${previous + 1}.`,
      });
      break;
    }
  }
  return conflicts;
}

export default function InternetPolicyEditor({
  defaultAction: initialDefaultAction,
  rules: initialRules,
  warnUnknownDomains: initialWarnUnknownDomains,
  warnUnknownBehavior: initialWarnUnknownBehavior,
  blockDirectIpNavigation: initialBlockDirectIpNavigation,
  allowHttpsOnly: initialAllowHttpsOnly,
}: InternetPolicyEditorProps) {
  const [defaultAction, setDefaultAction] = useState<InternetDefaultAction>(initialDefaultAction);
  const [rules, setRules] = useState<InternetRule[]>(normalizeInternetRules(initialRules));
  const [warnUnknownDomains, setWarnUnknownDomains] = useState<boolean>(initialWarnUnknownDomains);
  const [warnUnknownBehavior, setWarnUnknownBehavior] =
    useState<InternetWarnBehavior>(initialWarnUnknownBehavior);
  const [blockDirectIpNavigation, setBlockDirectIpNavigation] =
    useState<boolean>(initialBlockDirectIpNavigation);
  const [allowHttpsOnly, setAllowHttpsOnly] = useState<boolean>(initialAllowHttpsOnly);

  const conflicts = useMemo(() => detectConflicts(rules), [rules]);
  const effectiveWarnUnknownDomains = defaultAction === "allow" && warnUnknownDomains;
  const allowRuleCount = rules.filter((rule) => rule.action === "allow").length;
  const blockRuleCount = rules.filter((rule) => rule.action === "block").length;
  const warnRuleCount = rules.filter((rule) => rule.action === "warn").length;
  const allRulesBlocking = rules.length > 0 && blockRuleCount === rules.length;

  const updateRule = (index: number, patch: Partial<InternetRule>) => {
    setRules((current) =>
      current.map((rule, ruleIndex) =>
        ruleIndex === index
          ? {
              ...rule,
              ...patch,
              pattern: patch.pattern !== undefined ? normalizeInternetPattern(patch.pattern) : rule.pattern,
              warnBehavior:
                (patch.action ?? rule.action) === "warn"
                  ? (patch.warnBehavior ?? rule.warnBehavior ?? "log_only")
                  : undefined,
            }
          : rule,
      ),
    );
  };

  const moveRule = (index: number, direction: -1 | 1) => {
    setRules((current) => {
      const nextIndex = index + direction;
      if (nextIndex < 0 || nextIndex >= current.length) return current;
      const clone = [...current];
      [clone[index], clone[nextIndex]] = [clone[nextIndex], clone[index]];
      return clone;
    });
  };

  const removeRule = (index: number) => {
    setRules((current) => current.filter((_, ruleIndex) => ruleIndex !== index));
  };

  const addRule = () => {
    setRules((current) => [
      ...current,
      {
        id: createInternetRuleId(),
        pattern: "",
        matchType: "subdomain",
        action: "block",
      },
    ]);
  };

  const clearToAllowAll = () => {
    setDefaultAction("allow");
    setWarnUnknownDomains(false);
    setRules([]);
  };

  const clearToBlockAll = () => {
    setDefaultAction("block");
    setWarnUnknownDomains(false);
    setRules([]);
  };

  return (
    <div className="flex flex-col gap-4">
      <input type="hidden" name="internetDefaultAction" value={defaultAction} />
      <input type="hidden" name="internetRulesJson" value={JSON.stringify(rules)} />
      <input
        type="hidden"
        name="warnUnknownDomains"
        value={effectiveWarnUnknownDomains ? "on" : "off"}
      />
      <input type="hidden" name="warnUnknownBehavior" value={warnUnknownBehavior} />
      <input type="hidden" name="blockDirectIpNavigation" value={blockDirectIpNavigation ? "on" : "off"} />
      <input type="hidden" name="allowHttpsOnly" value={allowHttpsOnly ? "on" : "off"} />

      <div className="rounded-lg border border-border bg-card p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h3 className="text-sm font-medium text-foreground">Effective policy</h3>
            <p className="mt-1 text-xs text-muted-foreground">
              Rule table is the source of truth. Use quick actions for full reset.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button type="button" variant="outline" size="sm" onClick={clearToAllowAll}>
              Allow all
            </Button>
            <Button type="button" variant="outline" size="sm" onClick={clearToBlockAll}>
              Block all
            </Button>
          </div>
        </div>
        <div className="mt-3 rounded-md border border-border bg-secondary p-3 text-xs">
          <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
            Effective policy
          </p>
          <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            <div>
              <span className="text-muted-foreground">Default:</span>{" "}
              <span className="font-medium text-foreground">
                {defaultAction === "allow" ? "Allow" : "Block"}
              </span>
            </div>
            <div>
              <span className="text-muted-foreground">Rules:</span>{" "}
              <span className="font-medium text-foreground">
                {rules.length} total
                {allRulesBlocking ? " (all blocking)" : ""}
              </span>
            </div>
            <div>
              <span className="text-muted-foreground">Allows / Blocks / Warns:</span>{" "}
              <span className="font-medium text-foreground">
                {allowRuleCount} / {blockRuleCount} / {warnRuleCount}
              </span>
            </div>
            <div>
              <span className="text-muted-foreground">Unknown domains:</span>{" "}
              <span className="font-medium text-foreground">
                {defaultAction === "block"
                  ? "Blocked"
                  : effectiveWarnUnknownDomains
                    ? `Warn (${warnUnknownBehavior})`
                    : "Allowed"}
              </span>
            </div>
            <div>
              <span className="text-muted-foreground">IP navigation:</span>{" "}
              <span className="font-medium text-foreground">
                {blockDirectIpNavigation ? "Blocked" : "Allowed"}
              </span>
            </div>
            <div>
              <span className="text-muted-foreground">Protocol:</span>{" "}
              <span className="font-medium text-foreground">
                {allowHttpsOnly ? "HTTPS only" : "HTTP + HTTPS"}
              </span>
            </div>
          </div>
        </div>
      </div>

      <div className="rounded-lg border border-border bg-card p-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-medium text-foreground">Rules (first match wins)</h3>
            <p className="mt-0.5 text-xs text-muted-foreground">
              {defaultAction === "allow" ? "Exceptions (blocking/warning rules)" : "Allowed domains (override rules)"}.
              Rules are evaluated from top to bottom.
            </p>
          </div>
          <Button type="button" size="sm" variant="outline" onClick={addRule}>
            <Plus className="mr-1 h-3.5 w-3.5" />
            Add rule
          </Button>
        </div>

        {rules.length === 0 ? (
          <div className="mt-3 rounded-md border border-dashed border-border bg-secondary px-3 py-6 text-center text-xs text-muted-foreground">
            No rules yet. Add a rule to define explicit allow/block/warn behavior.
          </div>
        ) : (
          <div className="mt-3 overflow-x-auto">
            <table className="w-full min-w-[760px] border-collapse text-xs">
              <thead>
                <tr className="border-b border-border text-left text-muted-foreground">
                  <th className="px-2 py-2 font-medium">#</th>
                  <th className="px-2 py-2 font-medium">Domain pattern</th>
                  <th className="px-2 py-2 font-medium">Match type</th>
                  <th className="px-2 py-2 font-medium">Action</th>
                  <th className="px-2 py-2 font-medium">Controls</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule, index) => {
                  const conflict = conflicts.find((item) => item.ruleIndex === index);
                  return (
                    <tr key={rule.id} className="border-b border-border/70 align-top">
                      <td className="px-2 py-2.5">
                        <Badge variant="outline">{index + 1}</Badge>
                      </td>
                      <td className="px-2 py-2.5">
                        <Input
                          value={rule.pattern}
                          onChange={(event) => updateRule(index, { pattern: event.target.value })}
                          placeholder="github.com or *.internal.company"
                        />
                        {conflict ? (
                          <p
                            className={cn(
                              "mt-1 text-[11px]",
                              conflict.kind === "unreachable"
                                ? "text-severity-critical"
                                : "text-severity-medium",
                            )}
                          >
                            {conflict.message}
                          </p>
                        ) : null}
                      </td>
                      <td className="px-2 py-2.5">
                        <select
                          value={rule.matchType}
                          onChange={(event) =>
                            updateRule(index, { matchType: event.target.value as InternetRuleMatchType })
                          }
                          className="h-9 w-full rounded-md border border-input bg-background px-2 text-xs text-foreground"
                        >
                          <option value="exact">Exact domain</option>
                          <option value="subdomain">Include subdomains</option>
                          <option value="wildcard">Wildcard</option>
                        </select>
                      </td>
                      <td className="px-2 py-2.5">
                        <select
                          value={rule.action}
                          onChange={(event) =>
                            updateRule(index, { action: event.target.value as InternetRuleAction })
                          }
                          className={cn(
                            "h-9 w-full rounded-md border px-2 text-xs",
                            rule.action === "block"
                              ? "border-severity-critical/40 bg-severity-critical/10 text-severity-critical"
                              : rule.action === "warn"
                                ? "border-severity-medium/40 bg-severity-medium/10 text-severity-medium"
                                : "border-primary/40 bg-primary/10 text-primary",
                          )}
                        >
                          <option value="allow">Allow</option>
                          <option value="block">Block</option>
                          <option value="warn">Warn</option>
                        </select>
                      </td>
                      <td className="px-2 py-2.5">
                        <div className="flex items-center gap-1">
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon"
                            disabled={index === 0}
                            onClick={() => moveRule(index, -1)}
                          >
                            <ArrowUp className="h-3.5 w-3.5" />
                          </Button>
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon"
                            disabled={index === rules.length - 1}
                            onClick={() => moveRule(index, 1)}
                          >
                            <ArrowDown className="h-3.5 w-3.5" />
                          </Button>
                          <Button type="button" variant="ghost" size="icon" onClick={() => removeRule(index)}>
                            <Trash2 className="h-3.5 w-3.5 text-destructive" />
                          </Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="rounded-lg border border-border bg-card p-4">
        <h3 className="text-sm font-medium text-foreground">Global enforcement controls</h3>
        <p className="mt-1 text-xs text-muted-foreground">
          These checks apply before rule evaluation.
        </p>
        <div className="mt-3 flex flex-col gap-2.5 text-xs">
          <label
            className={cn(
              "flex items-start gap-2",
              defaultAction === "block" ? "cursor-not-allowed opacity-60" : "",
            )}
          >
            <input
              type="checkbox"
              checked={warnUnknownDomains}
              onChange={(event) => setWarnUnknownDomains(event.target.checked)}
              disabled={defaultAction === "block"}
              className="mt-0.5 h-4 w-4 rounded border-border bg-secondary"
            />
            <span>
              <span className="font-medium text-foreground">Warn on unknown domains</span>
              <span className="block text-muted-foreground">
                If no rule matches and default action is allow, generate a warning.
              </span>
            </span>
          </label>
          {defaultAction === "block" ? (
            <p className="ml-6 text-[11px] text-muted-foreground">
              Not applicable when default behavior is Block.
            </p>
          ) : null}

          {effectiveWarnUnknownDomains ? (
            <div className="ml-6">
              <label className="mb-1 block text-[11px] font-medium text-muted-foreground">
                Warn behavior
              </label>
              <select
                value={warnUnknownBehavior}
                onChange={(event) => setWarnUnknownBehavior(event.target.value as InternetWarnBehavior)}
                className="h-9 w-full max-w-xs rounded-md border border-input bg-background px-2 text-xs text-foreground"
              >
                <option value="log_only">Log only</option>
                <option value="require_confirmation">Require confirmation</option>
                <option value="alert">Send alert</option>
              </select>
            </div>
          ) : null}

          <label className="flex items-start gap-2">
            <input
              type="checkbox"
              checked={blockDirectIpNavigation}
              onChange={(event) => setBlockDirectIpNavigation(event.target.checked)}
              className="mt-0.5 h-4 w-4 rounded border-border bg-secondary"
            />
            <span>
              <span className="font-medium text-foreground">Block direct IP navigation</span>
              <span className="block text-muted-foreground">
                Prevent access to raw IP targets even if domain rules exist.
              </span>
            </span>
          </label>

          <label className="flex items-start gap-2">
            <input
              type="checkbox"
              checked={allowHttpsOnly}
              onChange={(event) => setAllowHttpsOnly(event.target.checked)}
              className="mt-0.5 h-4 w-4 rounded border-border bg-secondary"
            />
            <span>
              <span className="font-medium text-foreground">Allow HTTPS only</span>
              <span className="block text-muted-foreground">
                Block `http://` navigation at policy level.
              </span>
              {allowHttpsOnly ? (
                <span className="block text-[11px] text-muted-foreground">
                  HTTP targets are denied before domain rules are checked.
                </span>
              ) : null}
            </span>
          </label>
        </div>
      </div>

    </div>
  );
}
