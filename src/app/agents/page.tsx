/**
 * @fileoverview ClawSight SIEM module: platform/src/app/agents/page.tsx.
 */
import Link from "next/link";
import { Search, Terminal } from "lucide-react";
import AppShell from "@/components/app-shell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { discoverManagedAgents } from "@/lib/agents/discovery";
import { deriveManagedAgentKey } from "@/lib/agents/identity";
import { listManagedAgents } from "@/lib/agents/repository";
import { prisma } from "@/lib/prisma";
import AgentCard from "./_components/AgentCard";

type AgentsSearchParams = {
  q?: string;
  status?: "online" | "offline";
  sort?: "lastSeen" | "name";
};

type AgentRollup = {
  events24h: number;
  policyBlocks24h: number;
  alerts24h: number;
  channels: number;
  skills: number;
  plugins: number;
};

function formatDate(ts: Date): string {
  return ts.toLocaleString("en-US", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

function formatRelative(ts: Date): string {
  const diff = Date.now() - ts.getTime();
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return `${Math.round(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.round(diff / 3_600_000)}h ago`;
  return `${Math.round(diff / 86_400_000)}d ago`;
}

function readRuntimeMeta(meta: unknown): {
  host?: string;
  os?: string;
  openclaw?: string;
  plugin?: string;
} {
  if (!meta || typeof meta !== "object" || Array.isArray(meta)) return {};
  const rec = meta as Record<string, unknown>;
  const host = typeof rec.hostName === "string" ? rec.hostName : undefined;
  const osPlatform = typeof rec.osPlatform === "string" ? rec.osPlatform : undefined;
  const osRelease = typeof rec.osRelease === "string" ? rec.osRelease : undefined;
  const osArch = typeof rec.osArch === "string" ? rec.osArch : undefined;
  const os = [osPlatform, osRelease, osArch].filter(Boolean).join(" ");
  const openclaw = typeof rec.openclawVersion === "string" ? rec.openclawVersion : undefined;
  const plugin = typeof rec.pluginVersion === "string" ? rec.pluginVersion : undefined;
  return { host, os: os || undefined, openclaw, plugin };
}

function deriveDisplayName(agent: {
  displayName: string | null;
  reportedName: string | null;
  agentInstanceId: string | null;
  openclawAgentId: string | null;
  agentKey: string;
}): string {
  return (
    agent.displayName ||
    agent.reportedName ||
    agent.agentInstanceId ||
    agent.openclawAgentId ||
    agent.agentKey
  );
}

function isOnline(lastSeenAt: Date): boolean {
  return Date.now() - lastSeenAt.getTime() <= 10 * 60 * 1000;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function asNumber(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  return null;
}

function readInventoryCounts(payload: unknown): Pick<AgentRollup, "channels" | "skills" | "plugins"> | null {
  const payloadRec = asRecord(payload);
  const inventoryRec = asRecord(payloadRec?.inventory);
  if (!inventoryRec) return null;

  const runtimeRec = asRecord(inventoryRec.runtime);
  const runtimeChannelsRec = asRecord(runtimeRec?.channels);
  const runtimeSkillsRec = asRecord(runtimeRec?.skills);
  const runtimePluginsRec = asRecord(runtimeRec?.plugins);

  const accessRec = asRecord(inventoryRec.access);
  const accessChannels = Array.isArray(accessRec?.channels) ? (accessRec?.channels as unknown[]) : [];
  const enabledAccessChannels = accessChannels.filter((channel) => {
    const rec = asRecord(channel);
    if (!rec) return false;
    if (rec.enabled === false) return false;
    if (rec.configured === false) return false;
    return true;
  }).length;

  const runtimeRunningChannels = asNumber(runtimeChannelsRec?.runningAccounts);
  const runtimeConfiguredChannels = asNumber(runtimeChannelsRec?.configuredAccounts);
  const channels =
    (runtimeRunningChannels && runtimeRunningChannels > 0
      ? runtimeRunningChannels
      : runtimeConfiguredChannels && runtimeConfiguredChannels > 0
        ? runtimeConfiguredChannels
        : enabledAccessChannels);
  const skills =
    asNumber(runtimeSkillsRec?.ready) ??
    (Array.isArray(runtimeSkillsRec?.items)
      ? (runtimeSkillsRec?.items as unknown[]).filter((item) => asRecord(item)?.status === "ready").length
      : 0);
  const plugins =
    asNumber(runtimePluginsRec?.loaded) ??
    (Array.isArray(runtimePluginsRec?.items)
      ? (runtimePluginsRec?.items as unknown[]).filter((item) => asRecord(item)?.status === "loaded").length
      : 0);

  return {
    channels: Math.max(0, channels || 0),
    skills: Math.max(0, skills || 0),
    plugins: Math.max(0, plugins || 0),
  };
}

function isPolicyBlock(event: {
  category: string;
  action: string;
  outcome?: string | null;
  result?: string | null;
}): boolean {
  const outcome = String(event.outcome || "").toLowerCase();
  const result = String(event.result || "").toLowerCase();
  if (outcome === "block" || outcome === "blocked" || result === "block" || result === "blocked") {
    return true;
  }
  if (event.category === "policy" && /block|deny/.test(event.action.toLowerCase())) {
    return true;
  }
  return false;
}

export default async function AgentsPage({
  searchParams,
}: {
  searchParams: Promise<AgentsSearchParams>;
}) {
  const params = await searchParams;
  await discoverManagedAgents(350);
  const rows = await listManagedAgents({ limit: 300 });
  const since24h = new Date(new Date().getTime() - 24 * 60 * 60 * 1000);

  const recentSourceEvents = await prisma.telemetryEvent.findMany({
    where: { sourceIp: { not: null } },
    orderBy: [{ ts: "desc" }, { id: "desc" }],
    take: 5000,
    select: {
      projectId: true,
      agentInstanceId: true,
      openclawSessionId: true,
      openclawAgentId: true,
      openclawSessionKey: true,
      sourceIp: true,
    },
  });

  const recentEvents24h = await prisma.telemetryEvent.findMany({
    where: { ts: { gte: since24h } },
    select: {
      projectId: true,
      agentInstanceId: true,
      openclawSessionId: true,
      openclawAgentId: true,
      openclawSessionKey: true,
      category: true,
      action: true,
      outcome: true,
      result: true,
    },
  });

  const recentAlerts24h = await prisma.threatAlert.findMany({
    where: { ts: { gte: since24h }, alertModel: "execution_v2" },
    select: {
      projectId: true,
      agentInstanceId: true,
      openclawAgentId: true,
      openclawSessionKey: true,
    },
  });

  const recentInventorySnapshots = await prisma.telemetryEvent.findMany({
    where: {
      category: "agent",
      action: "inventory_snapshot",
    },
    orderBy: [{ ts: "desc" }, { id: "desc" }],
    take: 3000,
    select: {
      projectId: true,
      agentInstanceId: true,
      openclawSessionId: true,
      openclawAgentId: true,
      openclawSessionKey: true,
      payload: true,
    },
  });

  const sourceIpByAgentKey = new Map<string, string>();
  for (const event of recentSourceEvents) {
    const key = deriveManagedAgentKey({
      projectId: event.projectId,
      agentInstanceId: event.agentInstanceId,
      openclawSessionId: event.openclawSessionId,
      openclawAgentId: event.openclawAgentId,
      openclawSessionKey: event.openclawSessionKey,
    });
    if (!sourceIpByAgentKey.has(key) && event.sourceIp) sourceIpByAgentKey.set(key, event.sourceIp);
  }

  const rollupByAgentKey = new Map<string, AgentRollup>();
  for (const event of recentEvents24h) {
    const key = deriveManagedAgentKey({
      projectId: event.projectId,
      agentInstanceId: event.agentInstanceId,
      openclawSessionId: event.openclawSessionId,
      openclawAgentId: event.openclawAgentId,
      openclawSessionKey: event.openclawSessionKey,
    });
    const current = rollupByAgentKey.get(key) || {
      events24h: 0,
      policyBlocks24h: 0,
      alerts24h: 0,
      channels: 0,
      skills: 0,
      plugins: 0,
    };
    current.events24h += 1;
    if (isPolicyBlock(event)) current.policyBlocks24h += 1;
    rollupByAgentKey.set(key, current);
  }

  for (const alert of recentAlerts24h) {
    const key = deriveManagedAgentKey({
      projectId: alert.projectId,
      agentInstanceId: alert.agentInstanceId,
      openclawAgentId: alert.openclawAgentId,
      openclawSessionKey: alert.openclawSessionKey,
    });
    const current = rollupByAgentKey.get(key) || {
      events24h: 0,
      policyBlocks24h: 0,
      alerts24h: 0,
      channels: 0,
      skills: 0,
      plugins: 0,
    };
    current.alerts24h += 1;
    rollupByAgentKey.set(key, current);
  }

  for (const snapshot of recentInventorySnapshots) {
    const key = deriveManagedAgentKey({
      projectId: snapshot.projectId,
      agentInstanceId: snapshot.agentInstanceId,
      openclawSessionId: snapshot.openclawSessionId,
      openclawAgentId: snapshot.openclawAgentId,
      openclawSessionKey: snapshot.openclawSessionKey,
    });
    const current = rollupByAgentKey.get(key) || {
      events24h: 0,
      policyBlocks24h: 0,
      alerts24h: 0,
      channels: 0,
      skills: 0,
      plugins: 0,
    };
    if (current.channels > 0 || current.skills > 0 || current.plugins > 0) {
      continue;
    }
    const counts = readInventoryCounts(snapshot.payload);
    if (!counts) continue;
    current.channels = counts.channels;
    current.skills = counts.skills;
    current.plugins = counts.plugins;
    rollupByAgentKey.set(key, current);
  }

  const normalizedQuery = String(params.q || "")
    .trim()
    .toLowerCase();
  const statusFilter = params.status || "";
  const sort = params.sort || "lastSeen";

  const filtered = rows
    .map((agent) => {
      const runtime = readRuntimeMeta(agent.runtimeMeta);
      const sourceIp = sourceIpByAgentKey.get(agent.agentKey) || "-";
      const displayName = deriveDisplayName(agent);
      const online = isOnline(agent.lastSeenAt);
      const rollup = rollupByAgentKey.get(agent.agentKey) || {
        events24h: 0,
        policyBlocks24h: 0,
        alerts24h: 0,
        channels: 0,
        skills: 0,
        plugins: 0,
      };
      return { agent, runtime, sourceIp, displayName, online, rollup };
    })
    .filter((entry) => {
      if (statusFilter === "online" && !entry.online) return false;
      if (statusFilter === "offline" && entry.online) return false;
      if (!normalizedQuery) return true;
      const haystack = [
        entry.displayName,
        entry.agent.agentKey,
        entry.agent.notes || "",
        entry.runtime.host || "",
        entry.runtime.os || "",
        entry.sourceIp,
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(normalizedQuery);
    })
    .sort((a, b) => {
      if (sort === "name") return a.displayName.localeCompare(b.displayName);
      return b.agent.lastSeenAt.getTime() - a.agent.lastSeenAt.getTime();
    });

  return (
    <AppShell
      activeNav="agents"
      title="Agents"
      subtitle="OpenClaw instances"
    >
      <div className="flex flex-col gap-6">
        <form method="get" className="rounded-xl border border-border bg-card p-4">
          <div className="flex flex-wrap items-center gap-3">
            <div className="relative min-w-[280px] max-w-lg flex-1">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input name="q" defaultValue={params.q ?? ""} placeholder="Search agents..." className="h-9 pl-9" />
            </div>

            <select
              name="status"
              defaultValue={params.status ?? ""}
              className="h-9 min-w-[140px] rounded-md border border-border bg-card px-3 text-sm text-foreground"
            >
              <option value="">All status</option>
              <option value="online">Online</option>
              <option value="offline">Offline</option>
            </select>

            <select
              name="sort"
              defaultValue={params.sort ?? "lastSeen"}
              className="h-9 min-w-[150px] rounded-md border border-border bg-card px-3 text-sm text-foreground"
            >
              <option value="lastSeen">Sort: Last seen</option>
              <option value="name">Sort: Name</option>
            </select>

            <div className="ml-auto flex items-center gap-2">
              <Button type="submit" size="sm" className="h-9">
                Apply
              </Button>
              <Button type="button" variant="outline" size="sm" asChild className="h-9">
                <Link href="/agents">Reset</Link>
              </Button>
            </div>
          </div>
        </form>

        {filtered.length === 0 ? (
          <div className="flex flex-1 flex-col items-center justify-center gap-3 rounded-2xl border border-dashed border-border py-20">
            <div className="rounded-xl bg-muted p-3">
              <Terminal className="h-6 w-6 text-muted-foreground" />
            </div>
            <div className="text-center">
              <p className="text-sm font-medium text-foreground">No agents found</p>
              <p className="mt-1 max-w-xs text-xs text-muted-foreground">
                Try adjusting your search or filters. Agents appear automatically after plugin bootstrap.
              </p>
            </div>
          </div>
        ) : (
          <>
            <p className="text-xs text-muted-foreground">Showing {filtered.length} agents</p>
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 2xl:grid-cols-3">
              {filtered.map(({ agent, runtime, sourceIp, displayName, online, rollup }) => (
                <AgentCard
                  key={agent.agentKey}
                  href={`/agents/${encodeURIComponent(agent.agentKey)}`}
                  displayName={displayName}
                  description={
                    agent.notes?.trim() ||
                    "OpenClaw agent instance."
                  }
                  agentKey={agent.agentKey}
                  online={online}
                  events24h={rollup.events24h}
                  policyBlocks24h={rollup.policyBlocks24h}
                  alerts24h={rollup.alerts24h}
                  channelsCount={rollup.channels}
                  skillsCount={rollup.skills}
                  pluginsCount={rollup.plugins}
                  host={runtime.host || "-"}
                  os={runtime.os || "-"}
                  sourceIp={sourceIp}
                  lastSeenLabel={`Last seen ${formatRelative(agent.lastSeenAt)}`}
                />
              ))}
            </div>
          </>
        )}

        <p className="text-[11px] text-muted-foreground">Rendered at {formatDate(new Date())}</p>
      </div>
    </AppShell>
  );
}
