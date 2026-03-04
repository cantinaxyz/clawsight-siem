/**
 * @fileoverview ClawSight SIEM module: platform/src/app/safety/page.tsx.
 */
import Link from "next/link";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { Globe, ShieldAlert, Zap } from "lucide-react";
import AppShell from "@/components/app-shell";
import InternetPolicyEditor from "@/components/internet-policy-editor";
import FormSubmitButton from "@/components/ui/form-submit-button";
import TokenListInput from "@/components/ui/token-list-input";
import IntentPolicyV3 from "@/app/safety/_components/intent-policy-v3";
import {
  applySafetyConfig,
  loadSafetyConfig,
  parseCsvInput,
  type SafetyConfig,
  type TernaryMode,
} from "@/lib/safety-config";
import {
  normalizeInternetRules,
  type InternetDefaultAction,
  type InternetWarnBehavior,
} from "@/lib/internet-policy";
import { requireAdminServerActionAuth } from "@/lib/server-action-auth";
import { cn } from "@/lib/utils";

type TabId = "actions" | "internet" | "intent";
type SaveSignal = "actions" | "internet" | "error";

type SearchParams = {
  tab?: string;
  saved?: string;
};

function parseTab(value?: string): TabId {
  if (value === "actions") return "actions";
  if (value === "internet") return "internet";
  if (value === "intent" || value === "intent-policy") return "intent";
  return "actions";
}

function parseSaved(value?: string): SaveSignal | null {
  return value === "actions" || value === "internet" || value === "error" ? value : null;
}

function parseTernary(value: string): TernaryMode {
  return value === "allow" || value === "warn" || value === "block" ? value : "allow";
}

function safetyHref(tab: TabId, saved: SaveSignal): string {
  return `/safety?tab=${tab}&saved=${saved}`;
}

function saveMessage(signal: SaveSignal): string {
  if (signal === "actions") return "Action controls saved.";
  if (signal === "internet") return "Internet policy saved.";
  return "Failed to save settings. Please retry.";
}

function modeOptionClass(value: TernaryMode): string {
  if (value === "block") return "peer-checked:bg-severity-critical/15 peer-checked:text-severity-critical";
  if (value === "warn") return "peer-checked:bg-severity-medium/15 peer-checked:text-severity-medium";
  return "peer-checked:bg-primary/10 peer-checked:text-primary";
}

function renderModeSegment(name: string, current: TernaryMode) {
  const options: Array<{ value: TernaryMode; label: string }> = [
    { value: "allow", label: "Allow" },
    { value: "warn", label: "Warn" },
    { value: "block", label: "Block" },
  ];
  return (
    <div className="flex items-center rounded-md border border-border">
      {options.map((option) => (
        <label key={option.value} className="cursor-pointer">
          <input
            type="radio"
            name={name}
            value={option.value}
            defaultChecked={current === option.value}
            className="peer sr-only"
          />
          <span
            className={cn(
              "block px-3 py-1 text-xs font-medium text-muted-foreground transition-colors",
              modeOptionClass(option.value),
            )}
          >
            {option.label}
          </span>
        </label>
      ))}
    </div>
  );
}

function parseInternetDefaultAction(value: string): InternetDefaultAction {
  return value === "allow" || value === "block" ? value : "allow";
}

function parseInternetWarnBehavior(value: string): InternetWarnBehavior {
  return value === "log_only" || value === "require_confirmation" || value === "alert"
    ? value
    : "log_only";
}

function parseInternetRulesJson(value: string): unknown[] {
  if (!value.trim()) return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function saveActionsAction(formData: FormData) {
  "use server";
  await requireAdminServerActionAuth();
  const tab = parseTab(String(formData.get("tab") || "actions"));
  const cfg = await loadSafetyConfig();
  const next: SafetyConfig = {
    ...cfg,
    actions: {
      runCommands: cfg.actions.runCommands,
      allowedCommands: parseCsvInput(String(formData.get("allowedCommands") || "")),
      warnedCommands: parseCsvInput(String(formData.get("warnedCommands") || "")),
      blockedCommands: parseCsvInput(String(formData.get("blockedCommands") || "")),
      writeFiles: parseTernary(String(formData.get("writeFiles") || "")),
      installDownloads: parseTernary(String(formData.get("installDownloads") || "")),
      accessSecrets: parseTernary(String(formData.get("accessSecrets") || "")),
      payments: parseTernary(String(formData.get("payments") || "")),
    },
  };
  try {
    await applySafetyConfig(next);
    revalidatePath("/safety");
  } catch {
    redirect(safetyHref(tab, "error"));
  }
  redirect(safetyHref(tab, "actions"));
}

async function saveInternetAction(formData: FormData) {
  "use server";
  await requireAdminServerActionAuth();
  const tab = parseTab(String(formData.get("tab") || "internet"));
  const cfg = await loadSafetyConfig();
  const rulesRaw = parseInternetRulesJson(String(formData.get("internetRulesJson") || "[]"));
  const next: SafetyConfig = {
    ...cfg,
    internet: {
      defaultAction: parseInternetDefaultAction(String(formData.get("internetDefaultAction") || "")),
      rules: normalizeInternetRules(rulesRaw),
      warnUnknownDomains: String(formData.get("warnUnknownDomains") || "off") === "on",
      warnUnknownBehavior: parseInternetWarnBehavior(String(formData.get("warnUnknownBehavior") || "")),
      blockDirectIpNavigation: String(formData.get("blockDirectIpNavigation") || "off") === "on",
      allowHttpsOnly: String(formData.get("allowHttpsOnly") || "off") === "on",
    },
  };
  try {
    await applySafetyConfig(next);
    revalidatePath("/safety");
  } catch {
    redirect(safetyHref(tab, "error"));
  }
  redirect(safetyHref(tab, "internet"));
}

export default async function SafetyPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const params = await searchParams;
  const tab = parseTab(params.tab);
  const saved = parseSaved(params.saved);
  const cfg = await loadSafetyConfig();

  const tabLinks: Array<{
    id: TabId;
    label: string;
    icon: React.ComponentType<{ className?: string }>;
  }> = [
    { id: "actions", label: "Actions", icon: Zap },
    { id: "internet", label: "Internet", icon: Globe },
    { id: "intent", label: "Intent policy", icon: ShieldAlert },
  ];

  return (
    <AppShell
      activeNav="safety"
      title="Safety"
      subtitle="These are global safety rules and apply to all agents. For per-agent scope edit the safety policy in each agent page."
    >
      <div className="flex w-full flex-col gap-5">
        <div className="flex items-center border-b border-border">
          {tabLinks.map((item) => (
            <Link
              key={item.id}
              href={`/safety?tab=${item.id}`}
              className={cn(
                "flex items-center gap-1.5 border-b-2 px-4 py-2.5 text-sm font-medium transition-colors",
                tab === item.id
                  ? "border-primary text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground",
              )}
            >
              <item.icon className="h-3.5 w-3.5" />
              {item.label}
            </Link>
          ))}
        </div>

        {saved ? (
          <div
            className={cn(
              "rounded-md border px-3 py-2 text-sm",
              saved === "error"
                ? "border-destructive/40 bg-destructive/10 text-destructive"
                : "border-primary/30 bg-primary/5 text-primary",
            )}
          >
            {saveMessage(saved)}
          </div>
        ) : null}

        {tab === "actions" ? (
          <form action={saveActionsAction} className="flex flex-col gap-4">
            <input type="hidden" name="tab" value="actions" />
            <p className="text-xs text-muted-foreground">
              These controls define what your agent is allowed to do on the machine. Each control explicitly shows default behavior and exceptions.
            </p>

            <div className="rounded-lg border border-border bg-card">
              <div className="px-4 py-3">
                <h3 className="text-sm font-medium text-foreground">Run commands</h3>
                <p className="mt-0.5 text-xs text-muted-foreground">
                  {cfg.actions.runCommands === "block"
                    ? "List-based control. Unmatched commands are blocked by default."
                    : cfg.actions.runCommands === "warn"
                      ? "List-based control. Unmatched commands are warned by default."
                      : "List-based control. Unmatched commands are allowed by default."}
                </p>
              </div>
              <div className="border-t border-border p-4">
                <div className="grid grid-cols-1 gap-4 lg:grid-cols-3 lg:gap-6">
                  <TokenListInput
                    name="allowedCommands"
                    label="Allowed commands"
                    defaultValues={cfg.actions.allowedCommands}
                    placeholder="git, npm, pnpm"
                  />
                  <TokenListInput
                    name="warnedCommands"
                    label="Warn commands"
                    defaultValues={cfg.actions.warnedCommands}
                    placeholder="curl, which"
                  />
                  <TokenListInput
                    name="blockedCommands"
                    label="Blocked commands"
                    defaultValues={cfg.actions.blockedCommands}
                    placeholder="rm -rf, nc, bash -i"
                  />
                </div>
              </div>
            </div>

            <div className="rounded-lg border border-border bg-card">
              <div className="flex flex-col justify-between gap-3 px-4 py-3 md:flex-row md:items-center">
                <div className="flex-1">
                  <h3 className="text-sm font-medium text-foreground">Write files</h3>
                  <p className="mt-0.5 text-xs text-muted-foreground">Controls whether agents can create or modify files on disk.</p>
                </div>
                {renderModeSegment("writeFiles", cfg.actions.writeFiles)}
              </div>
            </div>

            <div className="rounded-lg border border-border bg-card">
              <div className="flex flex-col justify-between gap-3 px-4 py-3 md:flex-row md:items-center">
                <div className="flex-1">
                  <h3 className="text-sm font-medium text-foreground">Download & install</h3>
                  <p className="mt-0.5 text-xs text-muted-foreground">Controls file downloads and dependency installation actions.</p>
                </div>
                {renderModeSegment("installDownloads", cfg.actions.installDownloads)}
              </div>
            </div>

            <div className="rounded-lg border border-border bg-card">
              <div className="flex flex-col justify-between gap-3 px-4 py-3 md:flex-row md:items-center">
                <div className="flex-1">
                  <h3 className="text-sm font-medium text-foreground">Access secrets</h3>
                  <p className="mt-0.5 text-xs text-muted-foreground">Controls reading API keys, private keys, and environment secrets.</p>
                </div>
                {renderModeSegment("accessSecrets", cfg.actions.accessSecrets)}
              </div>
            </div>

            <div className="rounded-lg border border-border bg-card">
              <div className="flex flex-col justify-between gap-3 px-4 py-3 md:flex-row md:items-center">
                <div className="flex-1">
                  <h3 className="text-sm font-medium text-foreground">Payments</h3>
                  <p className="mt-0.5 text-xs text-muted-foreground">Controls payment-related tool actions when enabled in plugins.</p>
                </div>
                {renderModeSegment("payments", cfg.actions.payments)}
              </div>
            </div>

            <div>
              <FormSubmitButton type="submit" size="sm" pendingText="Saving actions...">
                Save Actions
              </FormSubmitButton>
            </div>
          </form>
        ) : null}

        {tab === "internet" ? (
          <form action={saveInternetAction} className="flex flex-col gap-4">
            <input type="hidden" name="tab" value="internet" />
            <p className="text-xs text-muted-foreground">
              The policy answers one question clearly: what happens when the agent tries to access a target URL or domain.
            </p>
            <InternetPolicyEditor
              defaultAction={cfg.internet.defaultAction}
              rules={cfg.internet.rules}
              warnUnknownDomains={cfg.internet.warnUnknownDomains}
              warnUnknownBehavior={cfg.internet.warnUnknownBehavior}
              blockDirectIpNavigation={cfg.internet.blockDirectIpNavigation}
              allowHttpsOnly={cfg.internet.allowHttpsOnly}
            />
            <div>
              <FormSubmitButton type="submit" size="sm" pendingText="Saving internet policy...">
                Save Internet Policy
              </FormSubmitButton>
            </div>
          </form>
        ) : null}

        {tab === "intent" ? <IntentPolicyV3 /> : null}
      </div>
    </AppShell>
  );
}
