/**
 * @fileoverview ClawSight SIEM module: platform/src/app/policies/page.tsx.
 */
import Link from "next/link";
import { Prisma, type PolicyRule } from "@prisma/client";
import { revalidatePath } from "next/cache";
import AppShell from "@/components/app-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { prisma } from "@/lib/prisma";

type PolicyScope = "tool" | "message" | "domain" | "ip";
type PolicyAction = "allow" | "block" | "modify";

const TOOL_PRESETS = ["web_search", "web_fetch", "read", "write", "exec", "message", "cron"];
const CHANNEL_PRESETS = ["discord", "telegram", "slack", "whatsapp", "webchat", "high-risk"];
const DOMAIN_PRESETS = ["openai.com", "anthropic.com", "google.com", "discord.com", "slack.com"];
const IP_PRESETS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"];

function text(formData: FormData, key: string): string {
  const raw = formData.get(key);
  return typeof raw === "string" ? raw.trim() : "";
}

function nullable(value: string): string | null {
  return value ? value : null;
}

function parseScope(value: string): PolicyScope {
  if (value === "domain") return "domain";
  if (value === "ip") return "ip";
  return value === "message" ? "message" : "tool";
}

function parseAction(value: string): PolicyAction {
  if (value === "allow" || value === "block" || value === "modify") {
    return value;
  }
  return "allow";
}

function parsePriority(value: string): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return 100;
  return Math.max(0, Math.floor(parsed));
}

function parseModifyParams(value: string): Prisma.InputJsonValue | null {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Prisma.InputJsonValue;
    }
    return null;
  } catch {
    return null;
  }
}

function uniqStrings(values: string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}

function matchSummary(rule: PolicyRule): string {
  const parts: string[] = [];
  if (rule.scope === "domain") {
    if (rule.contentContains) parts.push(`domain~"${rule.contentContains}"`);
  } else if (rule.scope === "ip") {
    if (rule.contentContains) parts.push(`ip=${rule.contentContains}`);
  } else if (rule.scope === "tool") {
    if (rule.toolName) parts.push(`tool=${rule.toolName}`);
    if (rule.commandContains) parts.push(`params*="${rule.commandContains}"`);
  } else {
    if (rule.channelId) parts.push(`channel=${rule.channelId}`);
    if (rule.toContains) parts.push(`to*="${rule.toContains}"`);
    if (rule.contentContains) parts.push(`content*="${rule.contentContains}"`);
  }
  return parts.length > 0 ? parts.join(" | ") : "any";
}

function modifySummary(rule: PolicyRule): string {
  if (rule.action !== "modify") return "-";
  if (rule.scope === "message") {
    return rule.modifyContent ? `set content (${rule.modifyContent.length} chars)` : "no content override";
  }
  if (rule.modifyParams && typeof rule.modifyParams === "object") {
    const keys = Object.keys(rule.modifyParams as Record<string, unknown>);
    return keys.length > 0 ? `params: ${keys.join(", ")}` : "no params override";
  }
  return "no params override";
}

async function createRuleAction(formData: FormData) {
  "use server";
  const name = text(formData, "name");
  const scope = parseScope(text(formData, "scope"));
  const action = parseAction(text(formData, "action"));
  const priority = parsePriority(text(formData, "priority"));
  const enabled = formData.get("enabled") === "on";
  const modifyParamsRaw = text(formData, "modifyParams");
  const domainPattern = text(formData, "domainContains") || text(formData, "domainPreset");
  const ipPattern = text(formData, "ipContains") || text(formData, "ipPreset");

  const toolName = text(formData, "toolName") || text(formData, "toolNamePreset");
  const channelId = text(formData, "channelId") || text(formData, "channelIdPreset");

  await prisma.policyRule.create({
    data: {
      name: name || `rule-${Date.now()}`,
      scope,
      scopeLevel: "global",
      managedAgentKey: null,
      action,
      priority,
      enabled,
      toolName: nullable(toolName),
      commandContains: nullable(text(formData, "commandContains")),
      channelId: nullable(channelId),
      toContains: nullable(text(formData, "toContains")),
      contentContains:
        scope === "domain"
          ? nullable(domainPattern)
          : scope === "ip"
            ? nullable(ipPattern)
            : nullable(text(formData, "contentContains")),
      modifyContent: nullable(text(formData, "modifyContent")),
      modifyParams: parseModifyParams(modifyParamsRaw) ?? Prisma.JsonNull,
      reason: nullable(text(formData, "reason")),
    },
  });

  revalidatePath("/policies");
}

async function createQuickRuleAction(formData: FormData) {
  "use server";
  const template = text(formData, "template");

  const ensure = async (data: Prisma.PolicyRuleCreateInput) => {
    const exists = await prisma.policyRule.findFirst({
      where: {
        name: data.name,
        scope: data.scope as string,
        action: data.action as string,
      },
      select: { id: true },
    });
    if (!exists) {
      await prisma.policyRule.create({ data });
    }
  };

  if (template === "block_internet") {
    await ensure({
      name: "Block internet search",
      scope: "tool",
      scopeLevel: "global",
      managedAgentKey: null,
      action: "block",
      priority: 50,
      enabled: true,
      toolName: "web_search",
      reason: "restricted internet access: web_search blocked",
    });
    await ensure({
      name: "Block internet fetch",
      scope: "tool",
      scopeLevel: "global",
      managedAgentKey: null,
      action: "block",
      priority: 51,
      enabled: true,
      toolName: "web_fetch",
      reason: "restricted internet access: web_fetch blocked",
    });
  }

  if (template === "allow_skills") {
    await ensure({
      name: "Allow loading SKILLS",
      scope: "tool",
      scopeLevel: "global",
      managedAgentKey: null,
      action: "allow",
      priority: 10,
      enabled: true,
      toolName: "read",
      commandContains: "skill",
      reason: "allow reading SKILL files",
    });
  }

  if (template === "block_exec") {
    await ensure({
      name: "Block exec tool",
      scope: "tool",
      scopeLevel: "global",
      managedAgentKey: null,
      action: "block",
      priority: 40,
      enabled: true,
      toolName: "exec",
      reason: "exec tool disabled by policy",
    });
  }

  revalidatePath("/policies");
}

async function toggleRuleAction(formData: FormData) {
  "use server";
  const id = Number(text(formData, "id"));
  if (!Number.isInteger(id) || id <= 0) return;
  const enabled = text(formData, "enabled") === "true";

  await prisma.policyRule.update({
    where: { id },
    data: { enabled },
  });
  revalidatePath("/policies");
}

async function deleteRuleAction(formData: FormData) {
  "use server";
  const id = Number(text(formData, "id"));
  if (!Number.isInteger(id) || id <= 0) return;

  await prisma.policyRule.delete({
    where: { id },
  });
  revalidatePath("/policies");
}

function actionBadgeClass(action: string): string {
  if (action === "block") return "border-destructive/40 bg-destructive/10 text-destructive";
  if (action === "modify") return "border-yellow-500/30 bg-yellow-500/10 text-yellow-300";
  return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
}

export default async function PoliciesPage() {
  const [rules, observedTools] = await Promise.all([
    prisma.policyRule.findMany({
      where: { scopeLevel: "global" },
      orderBy: [{ priority: "asc" }, { id: "asc" }],
    }),
    prisma.telemetryEvent.findMany({
      where: { openclawToolName: { not: null } },
      select: { openclawToolName: true },
      distinct: ["openclawToolName"],
      orderBy: { openclawToolName: "asc" },
      take: 200,
    }),
  ]);

  const toolOptions = uniqStrings([
    ...TOOL_PRESETS,
    ...observedTools.map((row) => row.openclawToolName || ""),
  ]);

  return (
    <AppShell
      activeNav="safety"
      title="Policy Rules"
      subtitle="Default is allow-all. First enabled match wins, ordered by priority. Domain/IP rules apply to tool + message requests."
    >
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Quick rules</CardTitle>
          <CardDescription>One-click presets for common restrictions.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          <form action={createQuickRuleAction}>
            <input type="hidden" name="template" value="block_internet" />
            <Button type="submit" size="sm" variant="outline">
              Restrict Internet
            </Button>
          </form>
          <form action={createQuickRuleAction}>
            <input type="hidden" name="template" value="allow_skills" />
            <Button type="submit" size="sm" variant="outline">
              Allow SKILLS
            </Button>
          </form>
          <form action={createQuickRuleAction}>
            <input type="hidden" name="template" value="block_exec" />
            <Button type="submit" size="sm" variant="outline">
              Block Exec
            </Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Prompt injection controls</CardTitle>
          <CardDescription>
            Manage regex/template + OpenAI checks for inbound prompt-injection attempts and tool-time blocking.
          </CardDescription>
        </CardHeader>
        <CardContent className="pt-0">
          <Button asChild size="sm" variant="outline">
            <Link href="/policies/prompt-injection">Open prompt injection controls</Link>
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Create rule</CardTitle>
          <CardDescription>
            Choose scope/action/target first. Use advanced fields only when needed.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form action={createRuleAction} className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-6">
            <Input name="name" placeholder="Rule name" required />
            <select
              name="scope"
              defaultValue="tool"
              className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground"
            >
              <option value="tool">tool</option>
              <option value="message">message</option>
              <option value="domain">domain</option>
              <option value="ip">ip</option>
            </select>
            <select
              name="action"
              defaultValue="block"
              className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground"
            >
              <option value="allow">allow</option>
              <option value="block">block</option>
              <option value="modify">modify</option>
            </select>
            <Input name="priority" type="number" defaultValue="100" placeholder="Priority" />
            <label className="flex items-center gap-2 rounded-md border border-input px-3 text-sm text-foreground">
              <input type="checkbox" name="enabled" defaultChecked />
              enabled
            </label>
            <Input name="reason" placeholder="Reason (optional)" />

            <select
              name="toolNamePreset"
              defaultValue=""
              className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground"
            >
              <option value="">Tool target (optional)</option>
              {toolOptions.map((tool) => (
                <option key={tool} value={tool}>
                  {tool}
                </option>
              ))}
            </select>
            <Input name="toolName" placeholder="Custom tool name (optional)" />
            <select
              name="channelIdPreset"
              defaultValue=""
              className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground"
            >
              <option value="">Channel target (optional)</option>
              {CHANNEL_PRESETS.map((channel) => (
                <option key={channel} value={channel}>
                  {channel}
                </option>
              ))}
            </select>
            <Input name="channelId" placeholder="Custom channel ID (optional)" />
            <Input name="toContains" placeholder="Recipient contains (optional)" />
            <Input name="contentContains" placeholder="Message contains (message scope)" />
            <select
              name="domainPreset"
              defaultValue=""
              className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground"
            >
              <option value="">Domain preset (domain scope)</option>
              {DOMAIN_PRESETS.map((domain) => (
                <option key={domain} value={domain}>
                  {domain}
                </option>
              ))}
            </select>
            <Input name="domainContains" placeholder="Domain contains (domain scope)" />
            <select
              name="ipPreset"
              defaultValue=""
              className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground"
            >
              <option value="">IP preset (ip scope)</option>
              {IP_PRESETS.map((ip) => (
                <option key={ip} value={ip}>
                  {ip}
                </option>
              ))}
            </select>
            <Input name="ipContains" placeholder="IP match (ip scope)" />

            <details className="xl:col-span-6 rounded-md border border-border p-3">
              <summary className="cursor-pointer text-sm font-medium text-foreground">
                Advanced options
              </summary>
              <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
                <Input name="commandContains" placeholder="Tool params contain text (optional)" />
                <Input name="modifyContent" placeholder="modify content (message + modify)" />
                <Input
                  name="modifyParams"
                  placeholder='modify params JSON (tool + modify), e.g. {"command":"echo safe"}'
                  className="xl:col-span-2"
                />
              </div>
            </details>

            <div className="flex items-center gap-2 sm:col-span-2 xl:col-span-6">
              <Button type="submit" size="sm">
                Save rule
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Rules</CardTitle>
          <CardDescription>First matching enabled rule wins. If none match, decision is allow.</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Priority</TableHead>
                <TableHead>State</TableHead>
                <TableHead>Scope / Action</TableHead>
                <TableHead>Name</TableHead>
                <TableHead>Match</TableHead>
                <TableHead>Modify</TableHead>
                <TableHead>Reason</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rules.map((rule) => (
                <TableRow key={rule.id}>
                  <TableCell>{rule.priority}</TableCell>
                  <TableCell>
                    <Badge className={rule.enabled ? "bg-emerald-500/10 text-emerald-300" : "bg-secondary text-muted-foreground"}>
                      {rule.enabled ? "enabled" : "disabled"}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline">{rule.scope}</Badge>
                      <Badge className={actionBadgeClass(rule.action)}>{rule.action}</Badge>
                    </div>
                  </TableCell>
                  <TableCell>{rule.name}</TableCell>
                  <TableCell className="max-w-[24rem] text-xs text-muted-foreground">{matchSummary(rule)}</TableCell>
                  <TableCell className="max-w-[18rem] text-xs text-muted-foreground">{modifySummary(rule)}</TableCell>
                  <TableCell className="max-w-[20rem] text-xs text-muted-foreground">{rule.reason || "-"}</TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Button asChild size="sm" variant="outline">
                        <Link href={`/policies/${rule.id}`}>Edit</Link>
                      </Button>
                      <form action={toggleRuleAction}>
                        <input type="hidden" name="id" value={rule.id} />
                        <input type="hidden" name="enabled" value={String(!rule.enabled)} />
                        <Button type="submit" size="sm" variant="outline">
                          {rule.enabled ? "Disable" : "Enable"}
                        </Button>
                      </form>
                      <form action={deleteRuleAction}>
                        <input type="hidden" name="id" value={rule.id} />
                        <Button type="submit" size="sm" variant="destructive">
                          Delete
                        </Button>
                      </form>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
              {rules.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={8}>No rules yet. All decisions are currently allow.</TableCell>
                </TableRow>
              ) : null}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </AppShell>
  );
}
