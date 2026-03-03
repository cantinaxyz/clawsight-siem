/**
 * @fileoverview ClawSight SIEM module: platform/src/app/policies/[id]/page.tsx.
 */
import Link from "next/link";
import { Prisma } from "@prisma/client";
import { notFound } from "next/navigation";
import { revalidatePath } from "next/cache";
import AppShell from "@/components/app-shell";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { prisma } from "@/lib/prisma";

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

type Params = {
  id: string;
};

export default async function PolicyRuleEditorPage({
  params,
}: {
  params: Promise<Params>;
}) {
  const { id } = await params;
  const ruleId = Number(id);
  if (!Number.isInteger(ruleId) || ruleId <= 0) {
    notFound();
  }

  const [rule, observedTools] = await Promise.all([
    prisma.policyRule.findUnique({
      where: { id: ruleId },
    }),
    prisma.telemetryEvent.findMany({
      where: { openclawToolName: { not: null } },
      select: { openclawToolName: true },
      distinct: ["openclawToolName"],
      orderBy: { openclawToolName: "asc" },
      take: 200,
    }),
  ]);

  if (!rule) {
    notFound();
  }

  const toolOptions = uniqStrings([
    ...TOOL_PRESETS,
    ...observedTools.map((row) => row.openclawToolName || ""),
  ]);

  async function updateRuleAction(formData: FormData) {
    "use server";
    const priority = parsePriority(text(formData, "priority"));
    const enabled = formData.get("enabled") === "on";
    const scopeRaw = text(formData, "scope");
    const actionRaw = text(formData, "action");
    const scope = scopeRaw === "domain" ? "domain" : scopeRaw === "ip" ? "ip" : scopeRaw === "message" ? "message" : "tool";
    const toolName = text(formData, "toolName") || text(formData, "toolNamePreset");
    const channelId = text(formData, "channelId") || text(formData, "channelIdPreset");
    const domainPattern = text(formData, "domainContains") || text(formData, "domainPreset");
    const ipPattern = text(formData, "ipContains") || text(formData, "ipPreset");

    await prisma.policyRule.update({
      where: { id: ruleId },
      data: {
        name: text(formData, "name") || `rule-${ruleId}`,
        scope,
        action: actionRaw === "allow" || actionRaw === "block" || actionRaw === "modify" ? actionRaw : "allow",
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
        modifyParams: parseModifyParams(text(formData, "modifyParams")) ?? Prisma.JsonNull,
        reason: nullable(text(formData, "reason")),
      },
    });

    revalidatePath("/policies");
    revalidatePath(`/policies/${ruleId}`);
  }

  async function deleteRuleAction() {
    "use server";
    await prisma.policyRule.delete({
      where: { id: ruleId },
    });
    revalidatePath("/policies");
  }

  const modifyParamsValue =
    rule.modifyParams && typeof rule.modifyParams === "object"
      ? JSON.stringify(rule.modifyParams, null, 2)
      : "";

  return (
    <AppShell
      activeNav="safety"
      title={`Edit Rule #${rule.id}`}
      subtitle="Custom values override dropdown presets when both are provided. Domain/IP rules use dedicated match fields."
    >
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">{rule.name}</CardTitle>
          <CardDescription>Update scope/action/conditions and save.</CardDescription>
        </CardHeader>
        <CardContent>
          <form action={updateRuleAction} className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-6">
            <Input name="name" defaultValue={rule.name} placeholder="Rule name" required />
            <select
              name="scope"
              defaultValue={rule.scope}
              className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground"
            >
              <option value="tool">tool</option>
              <option value="message">message</option>
              <option value="domain">domain</option>
              <option value="ip">ip</option>
            </select>
            <select
              name="action"
              defaultValue={rule.action}
              className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground"
            >
              <option value="allow">allow</option>
              <option value="block">block</option>
              <option value="modify">modify</option>
            </select>
            <Input name="priority" type="number" defaultValue={String(rule.priority)} />
            <label className="flex items-center gap-2 rounded-md border border-input px-3 text-sm text-foreground">
              <input type="checkbox" name="enabled" defaultChecked={rule.enabled} />
              enabled
            </label>
            <Input name="reason" defaultValue={rule.reason ?? ""} placeholder="Reason (optional)" />

            <select
              name="toolNamePreset"
              defaultValue=""
              className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground"
            >
              <option value="">Tool preset (optional)</option>
              {toolOptions.map((tool) => (
                <option key={tool} value={tool}>
                  {tool}
                </option>
              ))}
            </select>
            <Input name="toolName" defaultValue={rule.toolName ?? ""} placeholder="Custom tool name (optional)" />
            <select
              name="channelIdPreset"
              defaultValue=""
              className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground"
            >
              <option value="">Channel preset (optional)</option>
              {CHANNEL_PRESETS.map((channel) => (
                <option key={channel} value={channel}>
                  {channel}
                </option>
              ))}
            </select>
            <Input name="channelId" defaultValue={rule.channelId ?? ""} placeholder="Custom channel ID (optional)" />
            <Input name="toContains" defaultValue={rule.toContains ?? ""} placeholder="Recipient contains (optional)" />
            <Input
              name="contentContains"
              defaultValue={rule.scope === "message" ? (rule.contentContains ?? "") : ""}
              placeholder="Message contains (message scope)"
            />
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
            <Input
              name="domainContains"
              defaultValue={rule.scope === "domain" ? (rule.contentContains ?? "") : ""}
              placeholder="Domain contains (domain scope)"
            />
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
            <Input
              name="ipContains"
              defaultValue={rule.scope === "ip" ? (rule.contentContains ?? "") : ""}
              placeholder="IP match (ip scope)"
            />

            <details className="xl:col-span-6 rounded-md border border-border p-3">
              <summary className="cursor-pointer text-sm font-medium text-foreground">
                Advanced options
              </summary>
              <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
                <Input
                  name="commandContains"
                  defaultValue={rule.commandContains ?? ""}
                  placeholder="Tool params contain text (optional)"
                />
                <Input
                  name="modifyContent"
                  defaultValue={rule.modifyContent ?? ""}
                  placeholder="modify content (message + modify)"
                />
                <textarea
                  name="modifyParams"
                  defaultValue={modifyParamsValue}
                  className="min-h-36 w-full rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground xl:col-span-2"
                  placeholder='modify params JSON (tool + modify), e.g. {"command":"echo safe"}'
                />
              </div>
            </details>

            <div className="flex items-center gap-2 sm:col-span-2 xl:col-span-6">
              <Button type="submit" size="sm">
                Save changes
              </Button>
              <Button type="button" size="sm" variant="outline" asChild>
                <Link href="/policies">Back</Link>
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Delete rule</CardTitle>
          <CardDescription>This removes the rule immediately.</CardDescription>
        </CardHeader>
        <CardContent>
          <form action={deleteRuleAction} className="flex items-center gap-2">
            <Button type="submit" size="sm" variant="destructive">
              Delete rule
            </Button>
            <Button type="button" size="sm" variant="outline" asChild>
              <Link href="/policies">Cancel</Link>
            </Button>
          </form>
        </CardContent>
      </Card>
    </AppShell>
  );
}
