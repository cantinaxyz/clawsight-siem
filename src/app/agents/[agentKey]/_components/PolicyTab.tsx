/**
 * @fileoverview ClawSight SIEM module: platform/src/app/agents/[agentKey]/_components/PolicyTab.tsx.
 */
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import type { IntentPolicyConfig } from "@/lib/intent-policy";

type Rule = {
  id: number;
  priority: number;
  name: string;
  scope: string;
  action: string;
  toolName: string | null;
  commandContains: string | null;
  contentContains: string | null;
  channelId: string | null;
  reason: string | null;
};

type PolicyTabProps = {
  agentKey: string;
  policyProfile: string;
  globalIntentPolicy: IntentPolicyConfig;
  agentIntentPolicy: IntentPolicyConfig | null;
  rules: Rule[];
  updateAgentAction: (formData: FormData) => Promise<void>;
  createScopedRuleAction: (formData: FormData) => Promise<void>;
  deleteScopedRuleAction: (formData: FormData) => Promise<void>;
};

function actionBadge(action: string) {
  if (action === "allow") {
    return <Badge className="border-emerald-700 bg-emerald-600/20 text-emerald-300">Allow</Badge>;
  }
  if (action === "warn") {
    return <Badge className="border-yellow-700 bg-yellow-600/20 text-yellow-300">Warn</Badge>;
  }
  if (action === "block") {
    return <Badge className="border-rose-700 bg-rose-600/20 text-rose-300">Block</Badge>;
  }
  return <Badge className="border-sky-700 bg-sky-600/20 text-sky-300">Modify</Badge>;
}

export default function PolicyTab({
  agentKey,
  policyProfile,
  globalIntentPolicy,
  agentIntentPolicy,
  rules,
  updateAgentAction,
  createScopedRuleAction,
  deleteScopedRuleAction,
}: PolicyTabProps) {
  const effectiveIntent = agentIntentPolicy || globalIntentPolicy;
  const intentScopeLevel = agentIntentPolicy ? "agent" : "global";

  return (
    <div className="flex flex-col gap-6 p-4 md:p-8">
      <Card className="border-border">
        <CardContent className="p-5">
          <h3 className="mb-3 text-sm font-medium text-foreground">Policy Profile</h3>
          <form action={updateAgentAction} className="flex flex-col gap-3 md:flex-row md:items-end">
            <input type="hidden" name="agentKey" value={agentKey} />
            <input type="hidden" name="displayName" value="" />
            <input type="hidden" name="notes" value="" />
            <div className="grid min-w-[220px] grid-cols-1 gap-2 md:grid-cols-2">
              <select
                name="policyProfile"
                defaultValue={policyProfile}
                className="h-10 rounded-md border border-input bg-background px-3 text-sm text-foreground"
              >
                <option value="inherit_global">inherit_global</option>
                <option value="custom">custom</option>
              </select>
              <select
                name="intentScopeLevel"
                defaultValue={intentScopeLevel}
                className="h-10 rounded-md border border-input bg-background px-3 text-sm text-foreground"
              >
                <option value="global">Use global intent policy</option>
                <option value="agent">Custom intent policy</option>
              </select>
              <select
                name="intentMode"
                defaultValue={effectiveIntent.mode}
                className="h-10 rounded-md border border-input bg-background px-3 text-sm text-foreground"
              >
                <option value="off">off</option>
                <option value="audit">audit</option>
                <option value="enforce">enforce</option>
              </select>
              <Input
                name="intentWarnThreshold"
                type="number"
                defaultValue={String(effectiveIntent.driftWarnThreshold)}
                placeholder="Warn threshold"
              />
              <Input
                name="intentBlockThreshold"
                type="number"
                defaultValue={String(effectiveIntent.driftBlockThreshold)}
                placeholder="Block threshold"
              />
              <label className="inline-flex h-10 items-center gap-2 rounded-md border border-input px-3 text-sm text-foreground">
                <input
                  type="checkbox"
                  name="intentOutputSanitization"
                  defaultChecked={effectiveIntent.outputSanitization}
                  className="h-4 w-4 rounded border-border bg-secondary"
                />
                Output sanitization
              </label>
              <p className="text-xs text-muted-foreground">
                Agent-scoped rules are evaluated before global rules.
              </p>
            </div>
            <Button type="submit" size="sm">Save</Button>
          </form>
        </CardContent>
      </Card>

      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-foreground">Scoped Rules</h3>
      </div>

      <Card className="border-border">
        <CardContent className="space-y-4 p-4">
          <form action={createScopedRuleAction} className="grid grid-cols-1 gap-2 md:grid-cols-3">
            <input type="hidden" name="agentKey" value={agentKey} />
            <Input name="name" placeholder="Rule name" className="md:col-span-3" />
            <select
              name="scope"
              defaultValue="tool"
              className="h-10 rounded-md border border-input bg-background px-3 text-sm text-foreground"
            >
              <option value="tool">tool</option>
              <option value="message">message</option>
              <option value="domain">domain</option>
              <option value="ip">ip</option>
            </select>
            <select
              name="action"
              defaultValue="block"
              className="h-10 rounded-md border border-input bg-background px-3 text-sm text-foreground"
            >
              <option value="allow">allow</option>
              <option value="warn">warn</option>
              <option value="block">block</option>
              <option value="modify">modify</option>
            </select>
            <Input name="priority" defaultValue="100" placeholder="Priority" />
            <Input name="toolName" placeholder="Tool name" />
            <Input name="commandContains" placeholder="Command contains" />
            <Input name="contentContains" placeholder="Content/domain/ip contains" />
            <Input name="channelId" placeholder="Channel ID" />
            <Input name="toContains" placeholder="Recipient contains" />
            <Input name="reason" placeholder="Reason" className="md:col-span-2" />
            <div className="md:col-span-3">
              <Button type="submit" size="sm">Add scoped rule</Button>
            </div>
          </form>

          {rules.length === 0 ? (
            <div className="p-4 text-sm text-muted-foreground">No scoped rules yet.</div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="border-border hover:bg-transparent">
                  <TableHead className="w-[70px] text-muted-foreground">Priority</TableHead>
                  <TableHead className="text-muted-foreground">Scope</TableHead>
                  <TableHead className="text-muted-foreground">Action</TableHead>
                  <TableHead className="text-muted-foreground">Match</TableHead>
                  <TableHead className="text-right text-muted-foreground">Reason</TableHead>
                  <TableHead className="text-right text-muted-foreground">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rules.map((rule) => (
                  <TableRow key={rule.id} className="border-border">
                    <TableCell className="font-mono text-muted-foreground">{rule.priority}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-xs">{rule.scope}</Badge>
                    </TableCell>
                    <TableCell>{actionBadge(rule.action)}</TableCell>
                    <TableCell className="max-w-[260px] truncate font-mono text-xs text-foreground">
                      {rule.toolName ? `tool=${rule.toolName} ` : ""}
                      {rule.commandContains || rule.contentContains || rule.channelId || "any"}
                    </TableCell>
                    <TableCell className="max-w-[200px] truncate text-right text-xs text-muted-foreground">
                      {rule.reason || "-"}
                    </TableCell>
                    <TableCell className="text-right">
                      <form action={deleteScopedRuleAction}>
                        <input type="hidden" name="agentKey" value={agentKey} />
                        <input type="hidden" name="id" value={String(rule.id)} />
                        <Button type="submit" size="sm" variant="outline">Delete</Button>
                      </form>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
