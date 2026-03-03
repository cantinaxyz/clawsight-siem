/**
 * @fileoverview ClawSight SIEM module: platform/src/app/agents/[agentKey]/_components/ToolsTab.tsx.
 */
import Link from "next/link";
import type { ReactNode } from "react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Globe,
  HardDrive,
  Database,
  CreditCard,
  Lock,
  MessageSquare,
  Cpu,
  Box,
} from "lucide-react";

type ToolItem = {
  name: string;
  category: "network" | "filesystem" | "database" | "payment" | "crypto" | "messaging" | "compute" | "other";
  calls24h: number;
  lastUsedAt: Date | null;
  enabled: boolean;
};

type SkillItem = {
  name: string;
  status: "ready" | "disabled" | "blocked" | "missing";
  source?: string;
  bundled: boolean;
};

type PluginItem = {
  id: string;
  name: string;
  version?: string;
  status: "loaded" | "disabled" | "error" | "unknown";
  origin?: string;
};

type ToolsTabProps = {
  agentKey: string;
  tools: ToolItem[];
  skills: SkillItem[];
  plugins: PluginItem[];
};

const categoryIcons: Record<ToolItem["category"], ReactNode> = {
  network: <Globe className="h-3.5 w-3.5" />,
  filesystem: <HardDrive className="h-3.5 w-3.5" />,
  database: <Database className="h-3.5 w-3.5" />,
  payment: <CreditCard className="h-3.5 w-3.5" />,
  crypto: <Lock className="h-3.5 w-3.5" />,
  messaging: <MessageSquare className="h-3.5 w-3.5" />,
  compute: <Cpu className="h-3.5 w-3.5" />,
  other: <Box className="h-3.5 w-3.5" />,
};

const categoryColors: Record<ToolItem["category"], string> = {
  network: "border-sky-700/50 bg-sky-600/10 text-sky-400",
  filesystem: "border-amber-700/50 bg-amber-600/10 text-amber-400",
  database: "border-violet-700/50 bg-violet-600/10 text-violet-400",
  payment: "border-emerald-700/50 bg-emerald-600/10 text-emerald-400",
  crypto: "border-pink-700/50 bg-pink-600/10 text-pink-400",
  messaging: "border-blue-700/50 bg-blue-600/10 text-blue-400",
  compute: "border-orange-700/50 bg-orange-600/10 text-orange-400",
  other: "border-border bg-muted text-muted-foreground",
};

function formatRelative(value: Date | null): string {
  if (!value) return "-";
  const diff = Date.now() - value.getTime();
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return `${Math.round(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.round(diff / 3_600_000)}h ago`;
  return `${Math.round(diff / 86_400_000)}d ago`;
}

function SkillStatusBadge({ status }: { status: SkillItem["status"] }) {
  if (status === "ready") {
    return <Badge className="border-emerald-700 bg-emerald-600/20 text-emerald-300">ready</Badge>;
  }
  if (status === "missing") {
    return <Badge className="border-amber-700 bg-amber-600/20 text-amber-300">missing</Badge>;
  }
  if (status === "blocked") {
    return <Badge className="border-rose-700 bg-rose-600/20 text-rose-300">blocked</Badge>;
  }
  return <Badge className="border-muted bg-muted text-muted-foreground">disabled</Badge>;
}

function PluginStatusBadge({ status }: { status: PluginItem["status"] }) {
  if (status === "loaded") {
    return <Badge className="border-emerald-700 bg-emerald-600/20 text-emerald-300">loaded</Badge>;
  }
  if (status === "disabled") {
    return <Badge className="border-muted bg-muted text-muted-foreground">disabled</Badge>;
  }
  if (status === "error") {
    return <Badge className="border-rose-700 bg-rose-600/20 text-rose-300">error</Badge>;
  }
  return <Badge className="border-border bg-secondary text-secondary-foreground">unknown</Badge>;
}

export default function ToolsTab({ agentKey, tools, skills, plugins }: ToolsTabProps) {
  const totalTools = tools.length;
  const usedToday = tools.filter((tool) => tool.calls24h > 0).length;
  const neverUsed = tools.filter((tool) => !tool.lastUsedAt).length;
  const readySkills = skills.filter((skill) => skill.status === "ready").length;
  const loadedPlugins = plugins.filter((plugin) => plugin.status === "loaded").length;

  return (
    <div className="flex flex-col gap-5 p-4 md:p-8">
      <div className="grid grid-cols-3 gap-3">
        <Card className="border-border bg-secondary/30">
          <CardContent className="p-4">
            <div className="text-[11px] uppercase tracking-wider text-muted-foreground">Registered</div>
            <div className="mt-1 text-2xl font-semibold tabular-nums text-foreground">{totalTools}</div>
          </CardContent>
        </Card>
        <Card className="border-border bg-secondary/30">
          <CardContent className="p-4">
            <div className="text-[11px] uppercase tracking-wider text-muted-foreground">Used (24h)</div>
            <div className="mt-1 text-2xl font-semibold tabular-nums text-foreground">{usedToday}</div>
          </CardContent>
        </Card>
        <Card className="border-border bg-secondary/30">
          <CardContent className="p-4">
            <div className="text-[11px] uppercase tracking-wider text-muted-foreground">Never Used</div>
            <div className="mt-1 text-2xl font-semibold tabular-nums text-foreground">{neverUsed}</div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <Card className="border-border bg-secondary/30">
          <CardContent className="p-4">
            <div className="text-[11px] uppercase tracking-wider text-muted-foreground">Skills Ready</div>
            <div className="mt-1 text-2xl font-semibold tabular-nums text-foreground">
              {readySkills}/{skills.length}
            </div>
          </CardContent>
        </Card>
        <Card className="border-border bg-secondary/30">
          <CardContent className="p-4">
            <div className="text-[11px] uppercase tracking-wider text-muted-foreground">Plugins Loaded</div>
            <div className="mt-1 text-2xl font-semibold tabular-nums text-foreground">
              {loadedPlugins}/{plugins.length}
            </div>
          </CardContent>
        </Card>
      </div>

      {tools.length === 0 ? (
        <Card className="border-border">
          <CardContent className="p-6 text-center text-sm text-muted-foreground">
            No tools registered for this agent.
          </CardContent>
        </Card>
      ) : (
        <Card className="border-border">
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="border-border hover:bg-transparent">
                  <TableHead className="text-muted-foreground">Tool</TableHead>
                  <TableHead className="text-muted-foreground">Category</TableHead>
                  <TableHead className="text-muted-foreground">Last Used</TableHead>
                  <TableHead className="text-right text-muted-foreground">Calls (24h)</TableHead>
                  <TableHead className="text-right text-muted-foreground">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {[...tools]
                  .sort((a, b) => b.calls24h - a.calls24h)
                  .map((tool) => (
                    <TableRow key={tool.name} className="border-border">
                      <TableCell>
                        <Link
                          href={`/executions?agentKey=${encodeURIComponent(agentKey)}&tool=${encodeURIComponent(tool.name)}`}
                          className="font-mono text-sm text-primary transition-colors hover:text-primary/80"
                        >
                          {tool.name}
                        </Link>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={`gap-1.5 text-[11px] ${categoryColors[tool.category]}`}>
                          {categoryIcons[tool.category]}
                          {tool.category}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">{formatRelative(tool.lastUsedAt)}</TableCell>
                      <TableCell className="text-right font-mono text-sm tabular-nums text-foreground">
                        {tool.calls24h.toLocaleString()}
                      </TableCell>
                      <TableCell className="text-right">
                        {tool.enabled ? (
                          <Badge className="border-emerald-700 bg-emerald-600/20 text-emerald-300">Enabled</Badge>
                        ) : (
                          <Badge variant="secondary" className="text-muted-foreground">Disabled</Badge>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
        <Card className="border-border">
          <CardContent className="p-0">
            <div className="border-b border-border px-4 py-3">
              <h3 className="text-sm font-medium text-foreground">Installed Skills</h3>
            </div>
            {skills.length === 0 ? (
              <div className="p-6 text-sm text-muted-foreground">No skills metadata captured.</div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow className="border-border hover:bg-transparent">
                    <TableHead className="text-muted-foreground">Skill</TableHead>
                    <TableHead className="text-muted-foreground">Source</TableHead>
                    <TableHead className="text-right text-muted-foreground">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {skills.map((skill) => (
                    <TableRow key={skill.name} className="border-border">
                      <TableCell className="font-mono text-xs text-foreground">{skill.name}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {skill.source || (skill.bundled ? "openclaw-bundled" : "custom")}
                      </TableCell>
                      <TableCell className="text-right">
                        <SkillStatusBadge status={skill.status} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        <Card className="border-border">
          <CardContent className="p-0">
            <div className="border-b border-border px-4 py-3">
              <h3 className="text-sm font-medium text-foreground">Enabled Plugins</h3>
            </div>
            {plugins.length === 0 ? (
              <div className="p-6 text-sm text-muted-foreground">No plugin metadata captured.</div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow className="border-border hover:bg-transparent">
                    <TableHead className="text-muted-foreground">Plugin</TableHead>
                    <TableHead className="text-muted-foreground">Version</TableHead>
                    <TableHead className="text-right text-muted-foreground">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {plugins.map((plugin) => (
                    <TableRow key={plugin.id} className="border-border">
                      <TableCell className="text-xs font-medium text-foreground">
                        {plugin.name || plugin.id}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {plugin.version ? `v${plugin.version}` : "-"}
                      </TableCell>
                      <TableCell className="text-right">
                        <PluginStatusBadge status={plugin.status} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
