/**
 * @fileoverview ClawSight SIEM module: platform/src/app/policies/prompt-injection/page.tsx.
 */
import Link from "next/link";
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
import { PROMPT_INJECTION_TEMPLATES } from "@/lib/prompt-injection";
import { requireAdminServerActionAuth } from "@/lib/server-action-auth";

type PromptConfig = {
  id: number;
  llmEnabled: boolean;
  model: string;
  timeoutMs: number;
  failMode: string;
  updatedAt: Date;
};

type PromptRule = {
  id: number;
  name: string;
  enabled: boolean;
  priority: number;
  surface: string;
  action: string;
  patternType: string;
  patternValue: string | null;
  channelId: string | null;
  senderContains: string | null;
  toolName: string | null;
  llmCheck: boolean;
  reason: string | null;
  updatedAt: Date;
};

type PromptDecision = {
  id: number;
  createdAt: Date;
  surface: string;
  action: string;
  enforcement: string;
  reason: string | null;
  ruleId: number | null;
  toolName: string | null;
  channelId: string | null;
  sender: string | null;
  requestId: string | null;
  modelVerdict: string | null;
  modelConfidence: number | null;
};

function text(formData: FormData, key: string): string {
  const value = formData.get(key);
  return typeof value === "string" ? value.trim() : "";
}

function nullable(value: string): string | null {
  return value ? value : null;
}

function asPriority(value: string): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return 100;
  return Math.max(0, Math.floor(parsed));
}

function actionBadgeClass(action: string): string {
  if (action === "block") return "border-destructive/40 bg-destructive/10 text-destructive";
  if (action === "alert") return "border-yellow-500/30 bg-yellow-500/10 text-yellow-300";
  return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
}

async function ensureConfig() {
  await prisma.$executeRaw`
    INSERT INTO "PromptInjectionConfig" ("id","llmEnabled","model","timeoutMs","failMode","createdAt","updatedAt")
    VALUES (1, true, 'gpt-4.1-mini', 4500, 'fail_open', NOW(), NOW())
    ON CONFLICT ("id") DO NOTHING
  `;
}

async function saveConfigAction(formData: FormData) {
  "use server";
  await requireAdminServerActionAuth();
  await ensureConfig();
  const llmEnabled = formData.get("llmEnabled") === "on";
  const model = text(formData, "model") || "gpt-4.1-mini";
  const timeoutMsRaw = Number(text(formData, "timeoutMs"));
  const timeoutMs = Number.isFinite(timeoutMsRaw) ? Math.max(800, Math.floor(timeoutMsRaw)) : 4500;
  await prisma.$executeRaw`
    UPDATE "PromptInjectionConfig"
    SET
      "llmEnabled" = ${llmEnabled},
      "model" = ${model},
      "timeoutMs" = ${timeoutMs},
      "updatedAt" = NOW()
    WHERE "id" = 1
  `;
  revalidatePath("/policies/prompt-injection");
}

async function createRuleAction(formData: FormData) {
  "use server";
  await requireAdminServerActionAuth();
  const name = text(formData, "name") || `prompt-rule-${Date.now()}`;
  const surface = text(formData, "surface") || "both";
  const action = text(formData, "action") || "alert";
  const patternType = text(formData, "patternType") || "template";
  const patternValue = text(formData, "patternValue");
  const channelId = text(formData, "channelId");
  const senderContains = text(formData, "senderContains");
  const toolName = text(formData, "toolName");
  const reason = text(formData, "reason");
  const priority = asPriority(text(formData, "priority"));
  const llmCheck = formData.get("llmCheck") === "on";
  const enabled = formData.get("enabled") === "on";

  await prisma.$executeRaw`
    INSERT INTO "PromptInjectionRule"
      ("name","enabled","priority","surface","action","patternType","patternValue","channelId","senderContains","toolName","llmCheck","reason","createdAt","updatedAt")
    VALUES
      (${name}, ${enabled}, ${priority}, ${surface}, ${action}, ${patternType}, ${nullable(patternValue)}, ${nullable(channelId)}, ${nullable(senderContains)}, ${nullable(toolName)}, ${llmCheck}, ${nullable(reason)}, NOW(), NOW())
  `;
  revalidatePath("/policies/prompt-injection");
}

async function createTemplateAction(formData: FormData) {
  "use server";
  await requireAdminServerActionAuth();
  const template = text(formData, "template");
  if (!template) return;

  if (template === "block_download_execute") {
    await prisma.$executeRaw`
      INSERT INTO "PromptInjectionRule"
        ("name","enabled","priority","surface","action","patternType","patternValue","llmCheck","reason","createdAt","updatedAt")
      VALUES
        ('Block download + execute', true, 20, 'tool_call', 'block', 'template', 'download_execute', true, 'blocks download-and-execute prompt-injection behavior', NOW(), NOW())
    `;
  }

  if (template === "block_direct_ip_navigation") {
    await prisma.$executeRaw`
      INSERT INTO "PromptInjectionRule"
        ("name","enabled","priority","surface","action","patternType","patternValue","llmCheck","reason","createdAt","updatedAt")
      VALUES
        ('Block direct IP navigation', true, 25, 'tool_call', 'block', 'template', 'direct_ip_navigation', true, 'blocks direct IP navigation and fetch attempts', NOW(), NOW())
    `;
  }

  if (template === "alert_instruction_override") {
    await prisma.$executeRaw`
      INSERT INTO "PromptInjectionRule"
        ("name","enabled","priority","surface","action","patternType","patternValue","llmCheck","reason","createdAt","updatedAt")
      VALUES
        ('Alert instruction override', true, 40, 'inbound_message', 'alert', 'template', 'instruction_override', true, 'alerts on likely prompt-injection instruction override attempts', NOW(), NOW())
    `;
  }

  revalidatePath("/policies/prompt-injection");
}

async function toggleRuleAction(formData: FormData) {
  "use server";
  await requireAdminServerActionAuth();
  const id = Number(text(formData, "id"));
  const enabled = text(formData, "enabled") === "true";
  if (!Number.isInteger(id) || id <= 0) return;
  await prisma.$executeRaw`
    UPDATE "PromptInjectionRule"
    SET "enabled" = ${enabled}, "updatedAt" = NOW()
    WHERE "id" = ${id}
  `;
  revalidatePath("/policies/prompt-injection");
}

async function deleteRuleAction(formData: FormData) {
  "use server";
  await requireAdminServerActionAuth();
  const id = Number(text(formData, "id"));
  if (!Number.isInteger(id) || id <= 0) return;
  await prisma.$executeRaw`DELETE FROM "PromptInjectionRule" WHERE "id" = ${id}`;
  revalidatePath("/policies/prompt-injection");
}

export default async function PromptInjectionPoliciesPage() {
  await ensureConfig();
  const [configRows, rules, decisions] = await Promise.all([
    prisma.$queryRaw<Array<PromptConfig>>`
      SELECT "id","llmEnabled","model","timeoutMs","failMode","updatedAt"
      FROM "PromptInjectionConfig"
      WHERE "id" = 1
      LIMIT 1
    `,
    prisma.$queryRaw<Array<PromptRule>>`
      SELECT
        "id","name","enabled","priority","surface","action","patternType","patternValue","channelId","senderContains","toolName","llmCheck","reason","updatedAt"
      FROM "PromptInjectionRule"
      ORDER BY "priority" ASC, "id" ASC
      LIMIT 300
    `,
    prisma.$queryRaw<Array<PromptDecision>>`
      SELECT
        "id","createdAt","surface","action","enforcement","reason","ruleId","toolName","channelId","sender","requestId","modelVerdict","modelConfidence"
      FROM "PromptInjectionDecision"
      ORDER BY "createdAt" DESC
      LIMIT 120
    `,
  ]);

  const config = configRows[0] ?? {
    id: 1,
    llmEnabled: true,
    model: "gpt-4.1-mini",
    timeoutMs: 4500,
    failMode: "fail_open",
    updatedAt: new Date(),
  };

  return (
    <AppShell
      activeNav="safety"
      title="Prompt Injection Controls"
      subtitle="Inbound checks are advisory. Hard enforcement is applied on tool execution."
    >
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">OpenAI classifier settings</CardTitle>
          <CardDescription>Hybrid mode: regex/template first, then OpenAI for suspicious cases.</CardDescription>
        </CardHeader>
        <CardContent>
          <form action={saveConfigAction} className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-5">
            <label className="flex items-center gap-2 rounded-md border border-input px-3 text-sm text-foreground">
              <input type="checkbox" name="llmEnabled" defaultChecked={config.llmEnabled} />
              Enable OpenAI check
            </label>
            <Input name="model" defaultValue={config.model} placeholder="Model" />
            <Input name="timeoutMs" type="number" defaultValue={String(config.timeoutMs)} placeholder="Timeout ms" />
            <Input disabled value="fail_open" />
            <Button type="submit" size="sm">Save settings</Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Quick templates</CardTitle>
          <CardDescription>One-click prompt-injection baselines.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          <form action={createTemplateAction}>
            <input type="hidden" name="template" value="block_download_execute" />
            <Button type="submit" size="sm" variant="outline">Block download + execute</Button>
          </form>
          <form action={createTemplateAction}>
            <input type="hidden" name="template" value="block_direct_ip_navigation" />
            <Button type="submit" size="sm" variant="outline">Block direct IP navigation</Button>
          </form>
          <form action={createTemplateAction}>
            <input type="hidden" name="template" value="alert_instruction_override" />
            <Button type="submit" size="sm" variant="outline">Alert instruction override</Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Create prompt-injection rule</CardTitle>
          <CardDescription>Use presets first. Add regex only for specific custom patterns.</CardDescription>
        </CardHeader>
        <CardContent>
          <form action={createRuleAction} className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-6">
            <Input name="name" placeholder="Rule name" required />
            <select name="surface" defaultValue="both" className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground">
              <option value="both">both</option>
              <option value="inbound_message">inbound_message</option>
              <option value="tool_call">tool_call</option>
            </select>
            <select name="action" defaultValue="alert" className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground">
              <option value="alert">alert</option>
              <option value="block">block</option>
            </select>
            <select name="patternType" defaultValue="template" className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground">
              <option value="template">template</option>
              <option value="regex">regex</option>
              <option value="llm">llm</option>
            </select>
            <Input name="patternValue" placeholder="template key or regex (optional)" />
            <Input name="priority" type="number" defaultValue="100" placeholder="Priority" />
            <Input name="channelId" placeholder="Channel ID contains (optional)" />
            <Input name="senderContains" placeholder="Sender contains (optional)" />
            <Input name="toolName" placeholder="Tool name (optional)" />
            <Input name="reason" placeholder="Reason (optional)" />
            <label className="flex items-center gap-2 rounded-md border border-input px-3 text-sm text-foreground">
              <input type="checkbox" name="llmCheck" defaultChecked />
              run llm check
            </label>
            <label className="flex items-center gap-2 rounded-md border border-input px-3 text-sm text-foreground">
              <input type="checkbox" name="enabled" defaultChecked />
              enabled
            </label>
            <div className="sm:col-span-2 xl:col-span-6">
              <Button type="submit" size="sm">Save prompt-injection rule</Button>
            </div>
          </form>
          <div className="mt-4 flex flex-wrap gap-2 text-xs text-muted-foreground">
            {PROMPT_INJECTION_TEMPLATES.map((template) => (
              <Badge key={template.key} variant="outline">{template.key}</Badge>
            ))}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Rules</CardTitle>
          <CardDescription>First enabled matching rule is evaluated by priority.</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Priority</TableHead>
                <TableHead>State</TableHead>
                <TableHead>Surface / Action</TableHead>
                <TableHead>Name</TableHead>
                <TableHead>Pattern</TableHead>
                <TableHead>Selectors</TableHead>
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
                      <Badge variant="outline">{rule.surface}</Badge>
                      <Badge className={actionBadgeClass(rule.action)}>{rule.action}</Badge>
                    </div>
                  </TableCell>
                  <TableCell>{rule.name}</TableCell>
                  <TableCell className="max-w-[20rem] text-xs text-muted-foreground">
                    {rule.patternType}:{rule.patternValue || "-"}
                    {rule.llmCheck ? " | llm" : ""}
                  </TableCell>
                  <TableCell className="max-w-[16rem] text-xs text-muted-foreground">
                    {rule.channelId ? `channel:${rule.channelId} ` : ""}
                    {rule.senderContains ? `sender~${rule.senderContains} ` : ""}
                    {rule.toolName ? `tool:${rule.toolName}` : ""}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <form action={toggleRuleAction}>
                        <input type="hidden" name="id" value={rule.id} />
                        <input type="hidden" name="enabled" value={String(!rule.enabled)} />
                        <Button type="submit" size="sm" variant="outline">
                          {rule.enabled ? "Disable" : "Enable"}
                        </Button>
                      </form>
                      <form action={deleteRuleAction}>
                        <input type="hidden" name="id" value={rule.id} />
                        <Button type="submit" size="sm" variant="destructive">Delete</Button>
                      </form>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
              {rules.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7}>No prompt-injection rules yet.</TableCell>
                </TableRow>
              ) : null}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Recent prompt-injection decisions</CardTitle>
          <CardDescription>Captured attempts and classifier outcomes.</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Time</TableHead>
                <TableHead>Surface</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Rule</TableHead>
                <TableHead>LLM</TableHead>
                <TableHead>Context</TableHead>
                <TableHead>Reason</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {decisions.map((decision) => (
                <TableRow key={decision.id}>
                  <TableCell>{new Date(decision.createdAt).toLocaleString("en-US", { hour12: false })}</TableCell>
                  <TableCell>{decision.surface}</TableCell>
                  <TableCell>
                    <Badge className={actionBadgeClass(decision.action)}>{decision.action}</Badge>
                  </TableCell>
                  <TableCell>{decision.ruleId ? `pi:${decision.ruleId}` : "-"}</TableCell>
                  <TableCell>{decision.modelVerdict ? `${decision.modelVerdict} (${decision.modelConfidence ?? 0})` : "-"}</TableCell>
                  <TableCell className="max-w-[16rem] text-xs text-muted-foreground">
                    {decision.toolName ? `tool:${decision.toolName} ` : ""}
                    {decision.channelId ? `channel:${decision.channelId} ` : ""}
                    {decision.sender ? `sender:${decision.sender}` : ""}
                  </TableCell>
                  <TableCell className="max-w-[24rem] text-xs text-muted-foreground">{decision.reason || "-"}</TableCell>
                </TableRow>
              ))}
              {decisions.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7}>No prompt-injection decisions yet.</TableCell>
                </TableRow>
              ) : null}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <div className="flex items-center gap-2">
        <Button variant="outline" size="sm" asChild>
          <Link href="/policies">Back to policy rules</Link>
        </Button>
      </div>
    </AppShell>
  );
}
