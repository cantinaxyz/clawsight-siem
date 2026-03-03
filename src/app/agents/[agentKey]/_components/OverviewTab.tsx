/**
 * @fileoverview ClawSight SIEM module: platform/src/app/agents/[agentKey]/_components/OverviewTab.tsx.
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
  Activity,
  Box,
  Clock3,
  Globe,
  Hash,
  MessageSquare as MessageSquareIcon,
  Plug,
} from "lucide-react";

type OverviewDomain = {
  domain: string;
  calls24h: number;
  lastUsedAt: Date | null;
  resolvedIp: string | null;
  lastResolvedAt: Date | null;
};

type OverviewChannel = {
  id: string;
  status: "active" | "configured" | "missing_credentials" | "disabled";
  statusReason?: "plugin_disabled" | "not_running";
  enabled: boolean;
  connected: boolean;
  configured: boolean;
  credentialsPresent: boolean;
};

type OverviewPlugin = {
  id: string;
  name: string;
  version?: string;
  status: "loaded" | "disabled" | "error" | "unknown";
  origin?: string;
};

type OverviewSkill = {
  name: string;
  status: "ready" | "disabled" | "blocked" | "missing";
  source?: string;
  bundled: boolean;
};

type RuntimeCommand = {
  id: string;
  ok: boolean;
  durationMs: number;
};

type RecentExecution = {
  traceId: string;
  triggerType: "user" | "cron" | "webhook" | "retry" | "chain" | "system";
  status: "completed" | "error" | "blocked" | "running";
  durationMs?: number;
  startedAt: string;
};

type OverviewTabProps = {
  agentKey: string;
  events24h: number;
  traces24h: number;
  policyBlocks24h: number;
  alerts24h: number;
  errors24h: number;
  domains: OverviewDomain[];
  channels: OverviewChannel[];
  plugins: OverviewPlugin[];
  skills: OverviewSkill[];
  pluginSummary: {
    total: number;
    loaded: number;
    disabled: number;
    errors: number;
  };
  skillsSummary: {
    total: number;
    ready: number;
    disabled: number;
    blocked: number;
    missing: number;
  };
  recentExecutions: RecentExecution[];
  capabilities: string[];
  inventoryCollectedAt: Date | null;
  configPath: string | null;
  runtimeCommands: RuntimeCommand[];
};

const channelIcons: Record<string, ReactNode> = {
  slack: <Hash className="h-4 w-4" />,
  email: <MessageSquareIcon className="h-4 w-4" />,
  discord: <MessageSquareIcon className="h-4 w-4" />,
  telegram: <MessageSquareIcon className="h-4 w-4" />,
  whatsapp: <MessageSquareIcon className="h-4 w-4" />,
  sms: <MessageSquareIcon className="h-4 w-4" />,
};

function formatRelative(value: Date | null): string {
  if (!value) return "-";
  const diff = Date.now() - value.getTime();
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return `${Math.round(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.round(diff / 3_600_000)}h ago`;
  return `${Math.round(diff / 86_400_000)}d ago`;
}

function formatRelativeIso(value: string): string {
  return formatRelative(new Date(value));
}

function formatDuration(ms?: number): string {
  if (!ms) return "-";
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  if (ms < 3_600_000) return `${Math.round(ms / 60_000)}m`;
  return `${(ms / 3_600_000).toFixed(1)}h`;
}

function compactExecutionId(traceId: string): string {
  const parts = traceId.split(":").filter(Boolean);
  if (parts[0] === "msg") {
    const channel = (parts[1] || "msg").slice(0, 3).toUpperCase();
    const leaf = (parts[parts.length - 1] || "").replace(/[^a-zA-Z0-9]/g, "");
    return `${channel}-${(leaf || "EXEC").slice(-6).toUpperCase()}`;
  }
  if (parts[0] === "agent" && parts[parts.length - 1] === "bootstrap") {
    return "SYSTEM-BOOT";
  }
  return traceId.length > 16 ? `${traceId.slice(0, 16)}...` : traceId;
}

function statusClass(status: RecentExecution["status"]): string {
  if (status === "completed") return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
  if (status === "blocked") return "border-yellow-500/30 bg-yellow-500/10 text-yellow-300";
  if (status === "error") return "border-rose-500/30 bg-rose-500/10 text-rose-300";
  return "border-blue-500/30 bg-blue-500/10 text-blue-300";
}

function triggerLabel(trigger: RecentExecution["triggerType"]): string {
  if (trigger === "user") return "User";
  if (trigger === "cron") return "Cron";
  if (trigger === "webhook") return "Webhook";
  if (trigger === "retry") return "Retry";
  if (trigger === "chain") return "Chain";
  return "System";
}

function ActivityDonut({
  agentKey,
  events,
  policyBlocks,
  alerts,
  errors,
  executions,
}: {
  agentKey: string;
  events: number;
  policyBlocks: number;
  alerts: number;
  errors: number;
  executions: number;
}) {
  const total = Math.max(events + policyBlocks + alerts + errors + executions, 1);
  const eventsPct = (events / total) * 100;
  const policyPct = (policyBlocks / total) * 100;
  const alertsPct = (alerts / total) * 100;
  const errorsPct = (errors / total) * 100;
  const executionsPct = 100 - eventsPct - policyPct - alertsPct - errorsPct;

  const items = [
    {
      label: "Events",
      value: events,
      color: "#0ea5a8",
      href: `/events?agentKey=${encodeURIComponent(agentKey)}`,
    },
    {
      label: "Policy Blocks",
      value: policyBlocks,
      color: "#ca8a04",
      href: `/events?agentKey=${encodeURIComponent(agentKey)}&category=policy&outcome=block`,
    },
    {
      label: "Alerts",
      value: alerts,
      color: "#ea580c",
      href: `/alerts?agentKey=${encodeURIComponent(agentKey)}`,
    },
    {
      label: "Errors",
      value: errors,
      color: "#dc2626",
      href: `/events?agentKey=${encodeURIComponent(agentKey)}&outcome=error`,
    },
    {
      label: "Executions",
      value: executions,
      color: "#16a34a",
      href: `/executions?agentKey=${encodeURIComponent(agentKey)}`,
    },
  ];

  return (
    <div className="flex items-center gap-4">
      <div className="relative h-[106px] w-[106px] shrink-0">
        <div
          className="h-full w-full rounded-full"
          style={{
            background: `conic-gradient(
              #0ea5a8 0 ${eventsPct}%,
              #ca8a04 ${eventsPct}% ${eventsPct + policyPct}%,
              #ea580c ${eventsPct + policyPct}% ${eventsPct + policyPct + alertsPct}%,
              #dc2626 ${eventsPct + policyPct + alertsPct}% ${eventsPct + policyPct + alertsPct + errorsPct}%,
              #16a34a ${eventsPct + policyPct + alertsPct + errorsPct}% ${eventsPct + policyPct + alertsPct + errorsPct + executionsPct}%
            )`,
          }}
        />
        <div className="absolute inset-[18px] rounded-full bg-card" />
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-xs font-bold tabular-nums text-foreground">{total.toLocaleString()}</span>
          <span className="text-[9px] uppercase tracking-wider text-muted-foreground">Total</span>
        </div>
      </div>

      <div className="flex min-w-[190px] flex-col gap-0.5">
        {items.map((item) => (
          <Link
            key={item.label}
            href={item.href}
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-2 rounded-md px-1 py-0.5 transition-colors hover:bg-secondary/40"
          >
            <span className="h-2 w-2 rounded-full" style={{ backgroundColor: item.color }} />
            <span className="text-[10px] text-muted-foreground">{item.label}</span>
            <span className="ml-auto font-mono text-xs font-semibold tabular-nums text-foreground">
              {item.value.toLocaleString()}
            </span>
          </Link>
        ))}
      </div>
    </div>
  );
}

function PluginStatusBadge({ status }: { status: OverviewPlugin["status"] }) {
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

function SkillStatusBadge({ status }: { status: OverviewSkill["status"] }) {
  if (status === "ready") {
    return <Badge className="border-emerald-700 bg-emerald-600/20 px-1.5 py-0.5 text-[10px] text-emerald-300">ready</Badge>;
  }
  if (status === "missing") {
    return <Badge className="border-amber-700 bg-amber-600/20 px-1.5 py-0.5 text-[10px] text-amber-300">missing</Badge>;
  }
  if (status === "blocked") {
    return <Badge className="border-rose-700 bg-rose-600/20 px-1.5 py-0.5 text-[10px] text-rose-300">blocked</Badge>;
  }
  return <Badge className="border-muted bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">disabled</Badge>;
}

function channelStatusLabel(channel: OverviewChannel): {
  label: string;
  className: string;
} {
  if (channel.status === "active") {
    return {
      label: "Active",
      className: "text-emerald-300",
    };
  }
  if (channel.status === "configured") {
    return {
      label:
        channel.statusReason === "plugin_disabled"
          ? "Configured (plugin disabled)"
          : "Configured (not running)",
      className: "text-sky-300",
    };
  }
  if (channel.status === "missing_credentials") {
    return {
      label: "Missing credentials",
      className: "text-amber-300",
    };
  }
  return {
    label: "Disabled",
    className: "text-muted-foreground",
  };
}

export default function OverviewTab({
  agentKey,
  events24h,
  traces24h,
  policyBlocks24h,
  alerts24h,
  errors24h,
  domains,
  channels,
  plugins,
  skills,
  pluginSummary,
  skillsSummary,
  recentExecutions,
  capabilities,
  inventoryCollectedAt,
  configPath,
  runtimeCommands,
}: OverviewTabProps) {
  const topDomains = domains.slice(0, 3);
  const readySkills = skills.filter((skill) => skill.status === "ready");
  const loadedPlugins = plugins.filter((plugin) => plugin.status === "loaded");

  return (
    <div className="mx-auto w-full max-w-7xl px-3 py-3 md:px-4 md:py-4">
      <div className="space-y-5">
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
          <div className="space-y-5 lg:col-span-7">
            <Card className="rounded-2xl border-zinc-800 bg-gradient-to-b from-zinc-900/50 to-zinc-900/35 shadow-[inset_0_1px_0_rgba(255,255,255,0.03)]">
              <CardContent className="p-4">
                <h3 className="mb-2 border-b border-zinc-800 pb-1.5 text-sm font-medium text-foreground">Channels</h3>
                {channels.length === 0 ? (
                  <p className="text-xs text-muted-foreground">No channels configured.</p>
                ) : (
                  <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                    {channels.map((channel) => (
                      <div
                        key={channel.id}
                        className="flex items-center gap-2 rounded-xl border border-zinc-800 bg-zinc-900/60 px-3 py-2"
                      >
                        {(() => {
                          const status = channelStatusLabel(channel);
                          return (
                            <>
                              {channelIcons[channel.id] || <MessageSquareIcon className="h-4 w-4" />}
                              <div className="min-w-0">
                                <div className="truncate text-xs font-medium text-foreground">{channel.id}</div>
                                <div className={`text-[10px] ${status.className}`}>{status.label}</div>
                              </div>
                            </>
                          );
                        })()}
                      </div>
                    ))}
                  </div>
                )}
                <p className="mt-2 text-[10px] text-muted-foreground">
                  Active = runtime running/connected. Configured = available in config but not running.
                </p>
              </CardContent>
            </Card>

            <Card className="rounded-2xl border-zinc-800 bg-gradient-to-b from-zinc-900/50 to-zinc-900/35 shadow-[inset_0_1px_0_rgba(255,255,255,0.03)]">
              <CardContent className="p-4">
                <div className="mb-2 flex items-center justify-between">
                  <h3 className="border-b border-zinc-800 pb-1.5 text-sm font-medium text-foreground">Skills & Plugins</h3>
                  <span className="text-xs text-muted-foreground">
                    Ready skills {skillsSummary.ready}/{skillsSummary.total} · Loaded plugins {pluginSummary.loaded}/{pluginSummary.total}
                  </span>
                </div>
                <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                  <div className="min-w-0">
                    <div className="mb-1 text-[10px] uppercase tracking-wider text-muted-foreground">Enabled plugins</div>
                    {loadedPlugins.length === 0 ? (
                      <p className="text-xs text-muted-foreground">No loaded plugins.</p>
                    ) : (
                      <div className="max-h-[220px] space-y-1 overflow-auto pr-1">
                        {loadedPlugins.map((plugin) => (
                          <div
                            key={plugin.id}
                            className="flex items-center justify-between rounded-lg px-2 py-1 hover:bg-zinc-800/30"
                          >
                            <div className="min-w-0">
                              <div className="truncate text-xs font-medium text-foreground">{plugin.name || plugin.id}</div>
                              <div className="text-[11px] text-muted-foreground">{plugin.version ? `v${plugin.version}` : "-"}</div>
                            </div>
                            <PluginStatusBadge status={plugin.status} />
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="min-w-0">
                    <div className="mb-1 text-[10px] uppercase tracking-wider text-muted-foreground">Ready skills</div>
                    {readySkills.length === 0 ? (
                      <p className="text-xs text-muted-foreground">No ready skills.</p>
                    ) : (
                      <div className="max-h-[220px] space-y-1 overflow-auto pr-1">
                        {readySkills.map((skill) => (
                          <div
                            key={skill.name}
                            className="flex items-center justify-between rounded-lg px-2 py-1 hover:bg-zinc-800/30"
                          >
                            <span className="font-mono text-xs text-foreground">{skill.name}</span>
                            <SkillStatusBadge status={skill.status} />
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
                <div className="mt-2 pt-1">
                  <Link
                    href={`/agents/${encodeURIComponent(agentKey)}?tab=tools`}
                    className="text-xs text-primary hover:underline"
                  >
                    View full tools, skills, and plugins
                  </Link>
                </div>
              </CardContent>
            </Card>

            <Card className="rounded-2xl border-zinc-800 bg-zinc-900/20">
              <CardContent className="p-4">
                <h3 className="mb-2 border-b border-zinc-800 pb-1.5 text-sm font-medium text-foreground">Runtime</h3>
                <div className="space-y-2 text-xs text-muted-foreground">
                  <div className="flex items-center gap-2">
                    <Clock3 className="h-3.5 w-3.5" />
                    Snapshot: {formatRelative(inventoryCollectedAt)}
                  </div>
                  <div className="flex items-start gap-2">
                    <Activity className="mt-0.5 h-3.5 w-3.5" />
                    <div className="min-w-0">
                      <span>Config: </span>
                      <code className="break-all">{configPath || "-"}</code>
                    </div>
                  </div>
                </div>
                <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
                  {runtimeCommands.map((command) => (
                    <Badge
                      key={command.id}
                      className={
                        command.ok
                          ? "border-emerald-500/35 bg-emerald-500/10 text-emerald-300"
                          : "border-amber-400/40 bg-amber-500/10 text-amber-300"
                      }
                    >
                      {command.id} {command.ok ? "ok" : "failed"} ({command.durationMs}ms)
                    </Badge>
                  ))}
                </div>
                <div className="mt-2.5 flex flex-wrap gap-1.5">
                  {capabilities.length > 0 ? (
                    capabilities.map((capability) => (
                      <Badge key={capability} className="border-zinc-700 bg-zinc-900/50 text-muted-foreground">
                        {capability}
                      </Badge>
                    ))
                  ) : (
                    <span className="text-xs text-muted-foreground">No capability declarations in latest snapshot.</span>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>

          <div className="space-y-5 lg:col-span-5">
            <div className="grid grid-cols-1 gap-5 xl:grid-cols-1">
              <Card className="rounded-2xl border-zinc-800 bg-zinc-900/20">
                <CardContent className="p-3.5">
                  <h3 className="mb-2 text-sm font-medium text-foreground">Activity Distribution (24h)</h3>
                  <ActivityDonut
                    agentKey={agentKey}
                    events={events24h}
                    policyBlocks={policyBlocks24h}
                    alerts={alerts24h}
                    errors={errors24h}
                    executions={traces24h}
                  />
                </CardContent>
              </Card>

              <Card className="rounded-2xl border-zinc-800 bg-gradient-to-b from-zinc-900/40 to-zinc-900/25 shadow-[inset_0_1px_0_rgba(255,255,255,0.03)]">
                <CardContent className="p-4">
                  <div className="mb-2 flex items-center justify-between">
                    <h3 className="text-sm font-medium text-foreground">Recent Executions</h3>
                    <Link
                      href={`/executions?agentKey=${encodeURIComponent(agentKey)}`}
                      target="_blank"
                      rel="noreferrer"
                      className="text-xs text-primary hover:underline"
                    >
                      View all
                    </Link>
                  </div>
                  {recentExecutions.length === 0 ? (
                    <p className="text-xs text-muted-foreground">No executions recorded for this agent.</p>
                  ) : (
                    <div className="space-y-1.5">
                      {recentExecutions.map((execution) => (
                        <Link
                          key={execution.traceId}
                          href={`/executions?agentKey=${encodeURIComponent(agentKey)}&q=${encodeURIComponent(execution.traceId)}`}
                          target="_blank"
                          rel="noreferrer"
                          className="grid grid-cols-[1fr_auto_auto_auto] items-center gap-2 rounded-lg border border-border/60 bg-zinc-900/35 px-2.5 py-2 hover:bg-zinc-800/30"
                        >
                          <span className="font-mono text-sm font-medium text-foreground">{compactExecutionId(execution.traceId)}</span>
                          <Badge className="border-zinc-700 bg-zinc-900/50 text-muted-foreground">
                            {triggerLabel(execution.triggerType)}
                          </Badge>
                          <Badge className={statusClass(execution.status)}>{execution.status}</Badge>
                          <span className="text-xs text-muted-foreground">
                            {formatDuration(execution.durationMs)} • {formatRelativeIso(execution.startedAt)}
                          </span>
                        </Link>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>

            <Card className="rounded-2xl border-zinc-800 bg-zinc-900/20">
              <CardContent className="p-3.5">
                <div className="mb-2 flex items-center justify-between">
                  <h3 className="text-sm font-medium text-foreground">Network Activity (24h)</h3>
                  <Link
                    href={`/executions?agentKey=${encodeURIComponent(agentKey)}`}
                    target="_blank"
                    rel="noreferrer"
                    className="text-xs text-primary hover:underline"
                  >
                    View full network activity
                  </Link>
                </div>
                {topDomains.length === 0 ? (
                  <div className="flex h-[140px] items-center justify-center text-xs text-muted-foreground">
                    No network activity recorded.
                  </div>
                ) : (
                  <div className="min-h-[140px] overflow-x-auto">
                    <Table>
                      <TableHeader>
                        <TableRow className="border-border hover:bg-transparent">
                          <TableHead className="text-[10px] uppercase tracking-wider text-muted-foreground">Domain</TableHead>
                          <TableHead className="text-right text-[10px] uppercase tracking-wider text-muted-foreground">Calls</TableHead>
                          <TableHead className="text-right text-[10px] uppercase tracking-wider text-muted-foreground">Last Used</TableHead>
                          <TableHead className="text-[10px] uppercase tracking-wider text-muted-foreground">Resolved IP</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {topDomains.map((domain) => (
                          <TableRow key={domain.domain} className="border-border">
                            <TableCell>
                              <Link
                                href={`/executions?agentKey=${encodeURIComponent(agentKey)}&domain=${encodeURIComponent(domain.domain)}`}
                                target="_blank"
                                rel="noreferrer"
                                className="font-mono text-xs text-foreground transition-colors hover:text-primary"
                              >
                                {domain.domain}
                              </Link>
                            </TableCell>
                            <TableCell className="text-right font-mono text-xs tabular-nums text-muted-foreground">
                              {domain.calls24h.toLocaleString()}
                            </TableCell>
                            <TableCell className="text-right text-xs text-muted-foreground">
                              {formatRelative(domain.lastUsedAt)}
                            </TableCell>
                            <TableCell className="font-mono text-xs text-muted-foreground">
                              {domain.resolvedIp || "-"}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
}
