/**
 * @fileoverview ClawSight SIEM module: platform/src/app/agents/[agentKey]/page.tsx.
 */
import { notFound, redirect } from "next/navigation";
import { revalidatePath } from "next/cache";
import { Prisma } from "@prisma/client";
import AppShell from "@/components/app-shell";
import { buildManagedAgentEventWhere, buildManagedAgentSqlCondition } from "@/lib/agents/filter";
import {
  deleteManagedAgentAndData,
  getManagedAgent,
  updateManagedAgent,
} from "@/lib/agents/repository";
import { parseManagedAgentKey } from "@/lib/agents/identity";
import { loadIntentPolicyConfig, saveIntentPolicyConfig } from "@/lib/intent-policy";
import { prisma } from "@/lib/prisma";
import { requireAdminServerActionAuth } from "@/lib/server-action-auth";
import ConsoleHeader from "./_components/ConsoleHeader";
import TabNav, { AGENT_TABS, type AgentTabKey } from "./_components/TabNav";
import OverviewTab from "./_components/OverviewTab";
import TimelineTab from "./_components/TimelineTab";
import ToolsTab from "./_components/ToolsTab";
import PolicyTab from "./_components/PolicyTab";
import SettingsTab from "./_components/SettingsTab";

/**
 * Reads and trims a string field from form-data payloads used by server actions.
 */
function text(formData: FormData, key: string): string {
  const raw = formData.get(key);
  return typeof raw === "string" ? raw.trim() : "";
}

function readRuntimeMeta(meta: unknown): Record<string, string> {
  if (!meta || typeof meta !== "object" || Array.isArray(meta)) return {};
  const rec = meta as Record<string, unknown>;
  const out: Record<string, string> = {};
  const keys = [
    "hostName",
    "osPlatform",
    "osRelease",
    "osArch",
    "nodeVersion",
    "openclawVersion",
    "pluginVersion",
    "identityPath",
  ];
  for (const key of keys) {
    if (typeof rec[key] === "string" && rec[key]?.trim()) {
      out[key] = String(rec[key]);
    }
  }
  return out;
}

function fmt(ts: Date | null | undefined): string {
  if (!ts) return "-";
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

function toNumber(value: bigint | number): number {
  return typeof value === "bigint" ? Number(value) : value;
}

function mapTriggerType(sourceType: string | null | undefined): "user" | "cron" | "webhook" | "retry" | "chain" | "system" {
  const normalized = (sourceType || "").toLowerCase();
  if (normalized === "user") return "user";
  if (normalized === "cron") return "cron";
  if (normalized === "webhook") return "webhook";
  if (normalized === "retry") return "retry";
  if (normalized === "chain") return "chain";
  return "system";
}

function mapExecutionOutcome(
  status: string | null | undefined,
): "completed" | "error" | "blocked" | "running" {
  const normalized = (status || "").toLowerCase();
  if (normalized === "running") return "running";
  if (normalized === "blocked" || normalized === "block") return "blocked";
  if (normalized === "failed" || normalized === "error" || normalized === "partial") return "error";
  return "completed";
}

function buildManagedAgentAlertWhere(agentKey?: string | null): Prisma.ThreatAlertWhereInput | null {
  const parsed = parseManagedAgentKey(agentKey);
  if (!parsed) return null;

  const projectWhere: Prisma.ThreatAlertWhereInput =
    parsed.projectId === "default"
      ? { OR: [{ projectId: null }, { projectId: "" }, { projectId: "default" }] }
      : { projectId: parsed.projectId };

  if (parsed.kind === "inst") {
    return { AND: [projectWhere, { agentInstanceId: parsed.value }] };
  }
  if (parsed.kind === "oc") {
    return { AND: [projectWhere, { openclawAgentId: parsed.value }] };
  }
  if (parsed.kind === "sid") {
    return { AND: [projectWhere, { openclawSessionKey: parsed.value }] };
  }
  return { AND: [projectWhere, { openclawSessionKey: parsed.value }] };
}

function inferToolCategory(
  toolName: string,
): "network" | "filesystem" | "database" | "payment" | "crypto" | "messaging" | "compute" | "other" {
  const value = toolName.toLowerCase();
  if (value.includes("web") || value.includes("http") || value.includes("url") || value.includes("fetch") || value.includes("browser")) {
    return "network";
  }
  if (value.includes("file") || value.includes("read") || value.includes("write") || value.includes("edit") || value.includes("exec") || value.includes("shell") || value.includes("bash")) {
    return "filesystem";
  }
  if (value.includes("sql") || value.includes("db") || value.includes("query")) {
    return "database";
  }
  if (value.includes("pay") || value.includes("stripe")) {
    return "payment";
  }
  if (value.includes("wallet") || value.includes("chain") || value.includes("crypto")) {
    return "crypto";
  }
  if (value.includes("mail") || value.includes("sms") || value.includes("telegram") || value.includes("discord") || value.includes("slack")) {
    return "messaging";
  }
  if (value.includes("code") || value.includes("python") || value.includes("node") || value.includes("compute")) {
    return "compute";
  }
  return "other";
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function asString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => asString(item))
    .filter((item): item is string => Boolean(item));
}

function asBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

type ParsedInventorySnapshot = {
  collectedAt?: string;
  configPath?: string;
  identityPath?: string;
  hostName?: string;
  osPlatform?: string;
  osRelease?: string;
  osArch?: string;
  nodeVersion?: string;
  pluginVersion?: string;
  openclawVersion?: string;
  channels: Array<{
    id: string;
    enabled: boolean;
    configured: boolean;
    credentialsPresent: boolean;
  }>;
  capabilities: string[];
  plugins: {
    entries: Array<{ id: string; enabled: boolean }>;
    installs: Array<{ id: string; source?: string; version?: string }>;
  };
  skills: {
    configuredEntries: string[];
    discoveredWorkspaceSkills: string[];
    discoveredManagedSkills: string[];
  };
  runtime: {
    commands: Array<{
      id: "skillsList" | "pluginsList" | "channelsStatus";
      ok: boolean;
      durationMs: number;
      error?: string;
    }>;
    skills: {
      total: number;
      ready: number;
      disabled: number;
      blocked: number;
      missing: number;
      items: Array<{
        name: string;
        status: "ready" | "disabled" | "blocked" | "missing";
        source?: string;
        bundled: boolean;
      }>;
    };
    plugins: {
      total: number;
      loaded: number;
      disabled: number;
      errors: number;
      items: Array<{
        id: string;
        name?: string;
        status: "loaded" | "disabled" | "error" | "unknown";
        version?: string;
        origin?: string;
      }>;
    };
    channels: {
      totalAccounts: number;
      configuredAccounts: number;
      runningAccounts: number;
      connectedAccounts: number;
      items: Array<{
        channelId: string;
        accountId: string;
        enabled?: boolean;
        configured?: boolean;
        running?: boolean;
        connected?: boolean;
        lastError?: string;
        probeOk?: boolean;
      }>;
    };
  };
};

/**
 * Parses the plugin inventory snapshot payload into a typed UI-ready structure.
 *
 * The parser is defensive because snapshot payloads are treated as untrusted/optional
 * across plugin versions.
 */
function parseInventorySnapshot(payload: unknown): ParsedInventorySnapshot | null {
  const payloadRec = asRecord(payload);
  if (!payloadRec) return null;
  const inventoryRec = asRecord(payloadRec.inventory);
  if (!inventoryRec) return null;

  const sourceRec = asRecord(inventoryRec.source);
  const accessRec = asRecord(inventoryRec.access);
  const pluginsRec = asRecord(inventoryRec.plugins);
  const skillsRec = asRecord(inventoryRec.skills);
  const runtimeRec = asRecord(inventoryRec.runtime);

  const channelsRaw = Array.isArray(accessRec?.channels) ? accessRec?.channels : [];
  const channels = channelsRaw
    .map((item) => {
      const rec = asRecord(item);
      if (!rec) return null;
      const id = asString(rec.id);
      if (!id) return null;
      return {
        id,
        enabled: asBoolean(rec.enabled) !== false,
        configured: asBoolean(rec.configured) !== false,
        credentialsPresent: asBoolean(rec.credentialsPresent) === true,
      };
    })
    .filter((item): item is NonNullable<typeof item> => Boolean(item));

  const pluginEntriesRaw = Array.isArray(pluginsRec?.entries) ? pluginsRec?.entries : [];
  const pluginEntries = pluginEntriesRaw
    .map((item) => {
      const rec = asRecord(item);
      if (!rec) return null;
      const id = asString(rec.id);
      if (!id) return null;
      return {
        id,
        enabled: asBoolean(rec.enabled) !== false,
      };
    })
    .filter((item): item is NonNullable<typeof item> => Boolean(item));

  const pluginInstallsRaw = Array.isArray(pluginsRec?.installs) ? pluginsRec?.installs : [];
  const pluginInstalls = pluginInstallsRaw
    .map((item) => {
      const rec = asRecord(item);
      if (!rec) return null;
      const id = asString(rec.id);
      if (!id) return null;
      return {
        id,
        source: asString(rec.source),
        version: asString(rec.version),
      };
    })
    .filter((item): item is NonNullable<typeof item> => Boolean(item));

  const runtimeCommandsRec = asRecord(runtimeRec?.commands);
  const runtimeCommands = ([
    "skillsList",
    "pluginsList",
    "channelsStatus",
  ] as const).map((id) => {
    const rec = asRecord(runtimeCommandsRec?.[id]);
    return {
      id,
      ok: asBoolean(rec?.ok) === true,
      durationMs:
        typeof rec?.durationMs === "number" && Number.isFinite(rec.durationMs) ? rec.durationMs : 0,
      error: asString(rec?.error),
    };
  });

  const runtimeSkillsRec = asRecord(runtimeRec?.skills);
  const runtimeSkillItemsRaw = Array.isArray(runtimeSkillsRec?.items) ? runtimeSkillsRec?.items : [];
  const runtimeSkillItems = runtimeSkillItemsRaw
    .map((item) => {
      const rec = asRecord(item);
      if (!rec) return null;
      const name = asString(rec.name);
      if (!name) return null;
      const statusRaw = asString(rec.status);
      const status: ParsedInventorySnapshot["runtime"]["skills"]["items"][number]["status"] =
        statusRaw === "ready" || statusRaw === "disabled" || statusRaw === "blocked" || statusRaw === "missing"
          ? statusRaw
          : "missing";
      return {
        name,
        status,
        source: asString(rec.source),
        bundled: asBoolean(rec.bundled) === true,
      };
    })
    .filter((item): item is NonNullable<typeof item> => Boolean(item));

  const runtimePluginsRec = asRecord(runtimeRec?.plugins);
  const runtimePluginItemsRaw = Array.isArray(runtimePluginsRec?.items) ? runtimePluginsRec?.items : [];
  const runtimePluginItems = runtimePluginItemsRaw
    .map((item) => {
      const rec = asRecord(item);
      if (!rec) return null;
      const id = asString(rec.id);
      if (!id) return null;
      const statusRaw = asString(rec.status);
      const status: ParsedInventorySnapshot["runtime"]["plugins"]["items"][number]["status"] =
        statusRaw === "loaded" || statusRaw === "disabled" || statusRaw === "error" || statusRaw === "unknown"
          ? statusRaw
          : "unknown";
      return {
        id,
        name: asString(rec.name),
        status,
        version: asString(rec.version),
        origin: asString(rec.origin),
      };
    })
    .filter((item): item is NonNullable<typeof item> => Boolean(item));

  const runtimeChannelsRec = asRecord(runtimeRec?.channels);
  const runtimeChannelItemsRaw = Array.isArray(runtimeChannelsRec?.items) ? runtimeChannelsRec?.items : [];
  const runtimeChannelItems = runtimeChannelItemsRaw
    .map((item) => {
      const rec = asRecord(item);
      if (!rec) return null;
      const channelId = asString(rec.channelId);
      if (!channelId) return null;
      const accountId = asString(rec.accountId) || "default";
      return {
        channelId,
        accountId,
        enabled: asBoolean(rec.enabled),
        configured: asBoolean(rec.configured),
        running: asBoolean(rec.running),
        connected: asBoolean(rec.connected),
        lastError: asString(rec.lastError),
        probeOk: asBoolean(rec.probeOk),
      };
    })
    .filter((item): item is NonNullable<typeof item> => Boolean(item));

  return {
    collectedAt: asString(inventoryRec.collectedAt),
    configPath: asString(sourceRec?.configPath),
    identityPath: asString(sourceRec?.identityPath),
    hostName: asString(sourceRec?.hostName),
    osPlatform: asString(sourceRec?.osPlatform),
    osRelease: asString(sourceRec?.osRelease),
    osArch: asString(sourceRec?.osArch),
    nodeVersion: asString(sourceRec?.nodeVersion),
    pluginVersion: asString(sourceRec?.pluginVersion),
    openclawVersion: asString(sourceRec?.openclawVersion),
    channels,
    capabilities: asStringArray(accessRec?.capabilities),
    plugins: {
      entries: pluginEntries,
      installs: pluginInstalls,
    },
    skills: {
      configuredEntries: asStringArray(
        Array.isArray(skillsRec?.configuredEntries)
          ? (skillsRec?.configuredEntries as unknown[]).map((item) => asRecord(item)?.id)
          : [],
      ),
      discoveredWorkspaceSkills: asStringArray(skillsRec?.discoveredWorkspaceSkills),
      discoveredManagedSkills: asStringArray(skillsRec?.discoveredManagedSkills),
    },
    runtime: {
      commands: runtimeCommands,
      skills: {
        total:
          typeof runtimeSkillsRec?.total === "number" && Number.isFinite(runtimeSkillsRec.total)
            ? runtimeSkillsRec.total
            : runtimeSkillItems.length,
        ready:
          typeof runtimeSkillsRec?.ready === "number" && Number.isFinite(runtimeSkillsRec.ready)
            ? runtimeSkillsRec.ready
            : runtimeSkillItems.filter((item) => item.status === "ready").length,
        disabled:
          typeof runtimeSkillsRec?.disabled === "number" && Number.isFinite(runtimeSkillsRec.disabled)
            ? runtimeSkillsRec.disabled
            : runtimeSkillItems.filter((item) => item.status === "disabled").length,
        blocked:
          typeof runtimeSkillsRec?.blocked === "number" && Number.isFinite(runtimeSkillsRec.blocked)
            ? runtimeSkillsRec.blocked
            : runtimeSkillItems.filter((item) => item.status === "blocked").length,
        missing:
          typeof runtimeSkillsRec?.missing === "number" && Number.isFinite(runtimeSkillsRec.missing)
            ? runtimeSkillsRec.missing
            : runtimeSkillItems.filter((item) => item.status === "missing").length,
        items: runtimeSkillItems,
      },
      plugins: {
        total:
          typeof runtimePluginsRec?.total === "number" && Number.isFinite(runtimePluginsRec.total)
            ? runtimePluginsRec.total
            : runtimePluginItems.length,
        loaded:
          typeof runtimePluginsRec?.loaded === "number" && Number.isFinite(runtimePluginsRec.loaded)
            ? runtimePluginsRec.loaded
            : runtimePluginItems.filter((item) => item.status === "loaded").length,
        disabled:
          typeof runtimePluginsRec?.disabled === "number" && Number.isFinite(runtimePluginsRec.disabled)
            ? runtimePluginsRec.disabled
            : runtimePluginItems.filter((item) => item.status === "disabled").length,
        errors:
          typeof runtimePluginsRec?.errors === "number" && Number.isFinite(runtimePluginsRec.errors)
            ? runtimePluginsRec.errors
            : runtimePluginItems.filter((item) => item.status === "error").length,
        items: runtimePluginItems,
      },
      channels: {
        totalAccounts:
          typeof runtimeChannelsRec?.totalAccounts === "number" &&
          Number.isFinite(runtimeChannelsRec.totalAccounts)
            ? runtimeChannelsRec.totalAccounts
            : runtimeChannelItems.length,
        configuredAccounts:
          typeof runtimeChannelsRec?.configuredAccounts === "number" &&
          Number.isFinite(runtimeChannelsRec.configuredAccounts)
            ? runtimeChannelsRec.configuredAccounts
            : runtimeChannelItems.filter((item) => item.configured === true).length,
        runningAccounts:
          typeof runtimeChannelsRec?.runningAccounts === "number" &&
          Number.isFinite(runtimeChannelsRec.runningAccounts)
            ? runtimeChannelsRec.runningAccounts
            : runtimeChannelItems.filter((item) => item.running === true).length,
        connectedAccounts:
          typeof runtimeChannelsRec?.connectedAccounts === "number" &&
          Number.isFinite(runtimeChannelsRec.connectedAccounts)
            ? runtimeChannelsRec.connectedAccounts
            : runtimeChannelItems.filter((item) => item.connected === true).length,
        items: runtimeChannelItems,
      },
    },
  };
}

/**
 * Persists agent profile and optional agent-scoped intent policy overrides.
 */
async function updateAgentAction(formData: FormData) {
  "use server";
  await requireAdminServerActionAuth();
  const agentKey = text(formData, "agentKey");
  if (!agentKey) return;

  await updateManagedAgent({
    agentKey,
    displayName: text(formData, "displayName") || undefined,
    notes: text(formData, "notes") || undefined,
    policyProfile: text(formData, "policyProfile") || undefined,
  });

  const intentScopeLevel = text(formData, "intentScopeLevel") === "agent" ? "agent" : "global";
  if (intentScopeLevel === "agent") {
    const base = await loadIntentPolicyConfig({ scopeLevel: "global" });
    await saveIntentPolicyConfig(
      {
        ...base,
        mode: (text(formData, "intentMode") as "off" | "audit" | "enforce") || base.mode,
        driftWarnThreshold: Math.max(5, Number(text(formData, "intentWarnThreshold") || base.driftWarnThreshold) || base.driftWarnThreshold),
        driftBlockThreshold: Math.max(10, Number(text(formData, "intentBlockThreshold") || base.driftBlockThreshold) || base.driftBlockThreshold),
        outputSanitization: formData.get("intentOutputSanitization") === "on",
      },
      { scopeLevel: "agent", managedAgentKey: agentKey },
    );
  } else {
    const intentKey = `agent:${agentKey}`;
    await prisma.$executeRaw`DELETE FROM "IntentPolicyConfig" WHERE "configKey" = ${intentKey}`;
  }

  revalidatePath(`/agents/${encodeURIComponent(agentKey)}`);
  revalidatePath("/agents");
}

/**
 * Hard-deletes the managed agent and all scoped telemetry/policy artifacts.
 */
async function deleteAgentAction(formData: FormData) {
  "use server";
  await requireAdminServerActionAuth();
  const agentKey = text(formData, "agentKey");
  const confirm = text(formData, "confirm");
  if (!agentKey || confirm !== "DELETE") return;

  await deleteManagedAgentAndData(agentKey);
  revalidatePath("/agents");
  redirect("/agents");
}

/**
 * Creates an agent-scoped static policy rule from settings/policy tab forms.
 */
async function createScopedRuleAction(formData: FormData) {
  "use server";
  await requireAdminServerActionAuth();
  const agentKey = text(formData, "agentKey");
  if (!agentKey) return;

  await prisma.policyRule.create({
    data: {
      name: text(formData, "name") || `agent-rule-${Date.now()}`,
      scope: text(formData, "scope") || "tool",
      scopeLevel: "agent",
      managedAgentKey: agentKey,
      action: text(formData, "action") || "allow",
      priority: Math.max(0, Number(text(formData, "priority") || 100) || 100),
      enabled: true,
      toolName: text(formData, "toolName") || null,
      commandContains: text(formData, "commandContains") || null,
      channelId: text(formData, "channelId") || null,
      toContains: text(formData, "toContains") || null,
      contentContains: text(formData, "contentContains") || null,
      reason: text(formData, "reason") || null,
    },
  });

  revalidatePath(`/agents/${encodeURIComponent(agentKey)}`);
}

/**
 * Deletes a single agent-scoped static policy rule by numeric id.
 */
async function deleteScopedRuleAction(formData: FormData) {
  "use server";
  await requireAdminServerActionAuth();
  const agentKey = text(formData, "agentKey");
  const id = Number(text(formData, "id"));
  if (!agentKey || !Number.isInteger(id) || id <= 0) return;

  await prisma.policyRule.deleteMany({
    where: {
      id,
      scopeLevel: "agent",
      managedAgentKey: agentKey,
    },
  });
  revalidatePath(`/agents/${encodeURIComponent(agentKey)}`);
}

export default async function AgentDetailPage({
  params,
  searchParams,
}: {
  params: Promise<{ agentKey: string }>;
  searchParams: Promise<{ tab?: string }>;
}) {
  const { agentKey } = await params;
  const query = await searchParams;
  const decoded = decodeURIComponent(agentKey);
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);

  const [agent, rules, globalIntentPolicy, agentIntentConfigRows] = await Promise.all([
    getManagedAgent(decoded),
    prisma.policyRule.findMany({
      where: {
        scopeLevel: "agent",
        managedAgentKey: decoded,
      },
      orderBy: [{ priority: "asc" }, { id: "asc" }],
    }),
    loadIntentPolicyConfig({ scopeLevel: "global" }),
    prisma.$queryRaw<Array<{ configKey: string }>>(Prisma.sql`
      SELECT "configKey"
      FROM "IntentPolicyConfig"
      WHERE "configKey" = ${`agent:${decoded}`}
      LIMIT 1
    `),
  ]);

  if (!agent) {
    notFound();
  }
  const agentIntentPolicy = agentIntentConfigRows.length
    ? await loadIntentPolicyConfig({ scopeLevel: "agent", managedAgentKey: decoded, fallbackToGlobal: false })
    : null;

  const runtimeMeta = readRuntimeMeta(agent.runtimeMeta);

  const eventScopeWhere = buildManagedAgentEventWhere(decoded);
  const scopedEventWhere: Prisma.TelemetryEventWhereInput = eventScopeWhere
    ? { AND: [eventScopeWhere, { ts: { gte: since } }] }
    : { id: -1 };
  const scopedAnyEventWhere: Prisma.TelemetryEventWhereInput = eventScopeWhere ?? { id: -1 };
  const alertScopeWhere = buildManagedAgentAlertWhere(decoded);
  const scopedAlertWhere: Prisma.ThreatAlertWhereInput = alertScopeWhere
    ? { AND: [alertScopeWhere, { ts: { gte: since } }, { alertModel: "execution_v2" }] }
    : { id: -1 };

  const eventScopeSql =
    buildManagedAgentSqlCondition({
      agentKey: decoded,
      projectColumn: Prisma.sql`e."projectId"`,
      agentInstanceColumn: Prisma.sql`e."agentInstanceId"`,
      sessionIdColumn: Prisma.sql`e."openclawSessionId"`,
      openclawAgentColumn: Prisma.sql`e."openclawAgentId"`,
      sessionKeyColumn: Prisma.sql`e."openclawSessionKey"`,
    }) ?? Prisma.sql`FALSE`;

  const traceScopeSql =
    buildManagedAgentSqlCondition({
      agentKey: decoded,
      projectColumn: Prisma.sql`t."projectId"`,
      agentInstanceColumn: Prisma.sql`t."agentInstanceId"`,
      sessionIdColumn: Prisma.sql`t."openclawSessionId"`,
      openclawAgentColumn: Prisma.sql`t."openclawAgentId"`,
      sessionKeyColumn: Prisma.sql`t."openclawSessionKey"`,
    }) ?? Prisma.sql`FALSE`;

  const [
    events24h,
    policyBlocks24h,
    alerts24h,
    latestSourceEvent,
    latestInventoryEvent,
    toolStatsRows,
    domainUsageRows,
    traceStatusRows,
    recentTraceRows,
  ] = await Promise.all([
    prisma.telemetryEvent.count({ where: scopedEventWhere }),
    prisma.telemetryEvent.count({
      where: {
        AND: [scopedEventWhere, { category: "policy", outcome: "block" }],
      },
    }),
    prisma.threatAlert.count({
      where: scopedAlertWhere,
    }),
    prisma.telemetryEvent.findFirst({
      where: {
        AND: [scopedAnyEventWhere, { sourceIp: { not: null } }],
      },
      orderBy: [{ ts: "desc" }, { id: "desc" }],
      select: {
        ts: true,
        sourceIp: true,
        sourceHost: true,
      },
    }),
    prisma.telemetryEvent.findFirst({
      where: {
        AND: [scopedAnyEventWhere, { category: "agent", action: "inventory_snapshot" }],
      },
      orderBy: [{ ts: "desc" }, { id: "desc" }],
      select: {
        ts: true,
        payload: true,
      },
    }),
    prisma.$queryRaw<Array<{ tool: string; hits24h: bigint; lastTs: Date | null }>>(Prisma.sql`
      SELECT
        COALESCE(e."openclawToolName", '(unknown)') AS "tool",
        COUNT(*) FILTER (WHERE e."ts" >= ${since})::bigint AS "hits24h",
        MAX(e."ts") AS "lastTs"
      FROM "TelemetryEvent" e
      WHERE e."category" = 'tool'
        AND ${eventScopeSql}
      GROUP BY COALESCE(e."openclawToolName", '(unknown)')
      ORDER BY COUNT(*) FILTER (WHERE e."ts" >= ${since}) DESC, MAX(e."ts") DESC
      LIMIT 80
    `),
    prisma.$queryRaw<Array<{ value: string; hits24h: bigint; lastTs: Date | null }>>(Prisma.sql`
      SELECT
        o."value",
        COUNT(*) FILTER (WHERE e."ts" >= ${since})::bigint AS "hits24h",
        MAX(e."ts") AS "lastTs"
      FROM "TelemetryObservable" o
      JOIN "TelemetryEvent" e ON e."id" = o."eventId"
      WHERE o."kind" = 'domain'
        AND e."category" = 'tool'
        AND ${eventScopeSql}
      GROUP BY o."value"
      ORDER BY COUNT(*) FILTER (WHERE e."ts" >= ${since}) DESC, MAX(e."ts") DESC
      LIMIT 40
    `),
    prisma.$queryRaw<Array<{ status: string; hits: bigint }>>(Prisma.sql`
      SELECT t."status", COUNT(*)::bigint AS "hits"
      FROM "Trace" t
      WHERE t."lastEventTs" >= ${since}
        AND ${traceScopeSql}
      GROUP BY t."status"
      ORDER BY COUNT(*) DESC
    `),
    prisma.$queryRaw<
      Array<{
        traceId: string;
        status: string;
        sourceType: string;
        startedAt: Date;
        durationMs: number | null;
        spanCount: number;
        eventCount: number;
        errorCount: number;
        blockCount: number;
        rootExecutionId: string | null;
        openclawSessionKey: string | null;
      }>
    >(Prisma.sql`
      SELECT
        t."traceId",
        t."status",
        t."sourceType",
        t."startedAt",
        t."durationMs",
        t."spanCount",
        t."eventCount",
        t."errorCount",
        t."blockCount",
        t."rootExecutionId",
        t."openclawSessionKey"
      FROM "Trace" t
      WHERE ${traceScopeSql}
      ORDER BY t."startedAt" DESC
      LIMIT 220
    `),
  ]);

  const domainCandidates = domainUsageRows.map((row) => row.value).filter(Boolean);
  const domainResolutionRows =
    domainCandidates.length > 0
      ? await prisma.domainIpResolution.findMany({
          where: { domain: { in: domainCandidates } },
          orderBy: [{ lastSeenAt: "desc" }],
          select: {
            domain: true,
            ip: true,
            lastSeenAt: true,
          },
        })
      : [];
  const domainResolutionByDomain = new Map<string, { ip: string; lastSeenAt: Date }>();
  for (const row of domainResolutionRows) {
    if (!domainResolutionByDomain.has(row.domain)) {
      domainResolutionByDomain.set(row.domain, { ip: row.ip, lastSeenAt: row.lastSeenAt });
    }
  }

  const traces24h = traceStatusRows.reduce((sum, row) => sum + toNumber(row.hits), 0);
  const errors24h = traceStatusRows.reduce((sum, row) => {
    const status = row.status.toLowerCase();
    if (status === "error" || status === "failed" || status === "partial") {
      return sum + toNumber(row.hits);
    }
    return sum;
  }, 0);
  const configuredAccess = parseInventorySnapshot(latestInventoryEvent?.payload);
  const domainInventory = domainUsageRows
    .map((row) => {
      const resolution = domainResolutionByDomain.get(row.value);
      return {
        domain: row.value,
        calls24h: toNumber(row.hits24h),
        lastUsedAt: row.lastTs,
        resolvedIp: resolution?.ip || null,
        lastResolvedAt: resolution?.lastSeenAt || null,
      };
    })
    .filter((row) => row.calls24h > 0)
    .slice(0, 20);
  const toolInventory = toolStatsRows.map((row) => ({
    name: row.tool,
    category: inferToolCategory(row.tool),
    calls24h: toNumber(row.hits24h),
    lastUsedAt: row.lastTs,
    enabled: true,
  }));

  const channelsMap = new Map<
    string,
    {
      id: string;
      status: "active" | "configured" | "missing_credentials" | "disabled";
      statusReason?: "plugin_disabled" | "not_running";
      enabled: boolean;
      connected: boolean;
      configured: boolean;
      credentialsPresent: boolean;
    }
  >();
  const runtimePluginStatusById = new Map<string, "loaded" | "disabled" | "error" | "unknown">();
  for (const plugin of configuredAccess?.runtime.plugins.items || []) {
    runtimePluginStatusById.set(plugin.id.toLowerCase(), plugin.status);
  }
  for (const channel of configuredAccess?.runtime.channels.items || []) {
    const enabled = channel.enabled !== false;
    const configured = channel.configured !== false;
    const connected = channel.connected === true;
    const running = channel.running === true;
    const status: "active" | "configured" | "missing_credentials" | "disabled" =
      enabled && (running || connected)
        ? "active"
        : enabled && configured
          ? "configured"
          : "disabled";

    channelsMap.set(channel.channelId, {
      id: channel.channelId,
      status,
      statusReason: status === "configured" ? "not_running" : undefined,
      enabled,
      connected,
      configured,
      credentialsPresent: false,
    });
  }
  for (const channel of configuredAccess?.channels || []) {
    if (!channelsMap.has(channel.id)) {
      const pluginStatus = runtimePluginStatusById.get(channel.id.toLowerCase());
      const status: "active" | "configured" | "missing_credentials" | "disabled" =
        !channel.enabled
          ? "disabled"
          : channel.credentialsPresent
            ? "configured"
            : "missing_credentials";
      const statusReason =
        status === "configured"
          ? pluginStatus && pluginStatus !== "loaded"
            ? "plugin_disabled"
            : "not_running"
          : undefined;

      channelsMap.set(channel.id, {
        id: channel.id,
        status,
        statusReason,
        enabled: channel.enabled,
        connected: false,
        configured: channel.configured,
        credentialsPresent: channel.credentialsPresent,
      });
    }
  }
  const channelInventory = Array.from(channelsMap.values()).sort((a, b) => a.id.localeCompare(b.id));

  const pluginMap = new Map<
    string,
    {
      id: string;
      name: string;
      version?: string;
      status: "loaded" | "disabled" | "error" | "unknown";
      origin?: string;
    }
  >();
  for (const plugin of configuredAccess?.runtime.plugins.items || []) {
    pluginMap.set(plugin.id, {
      id: plugin.id,
      name: plugin.name || plugin.id,
      version: plugin.version,
      status: plugin.status,
      origin: plugin.origin,
    });
  }
  for (const entry of configuredAccess?.plugins.entries || []) {
    if (!pluginMap.has(entry.id)) {
      const install = configuredAccess?.plugins.installs.find((item) => item.id === entry.id);
      pluginMap.set(entry.id, {
        id: entry.id,
        name: entry.id,
        version: install?.version,
        status: entry.enabled ? "loaded" : "disabled",
        origin: install?.source,
      });
    }
  }
  const pluginInventory = Array.from(pluginMap.values()).sort((a, b) => a.name.localeCompare(b.name));

  const skillsInventory = [...(configuredAccess?.runtime.skills.items || [])].sort((a, b) =>
    a.name.localeCompare(b.name),
  );
  const pluginSummary = {
    total: configuredAccess?.runtime.plugins.total ?? pluginInventory.length,
    loaded:
      configuredAccess?.runtime.plugins.loaded ??
      pluginInventory.filter((plugin) => plugin.status === "loaded").length,
    disabled:
      configuredAccess?.runtime.plugins.disabled ??
      pluginInventory.filter((plugin) => plugin.status === "disabled").length,
    errors:
      configuredAccess?.runtime.plugins.errors ??
      pluginInventory.filter((plugin) => plugin.status === "error").length,
  };
  const skillsSummary = {
    total: configuredAccess?.runtime.skills.total ?? skillsInventory.length,
    ready:
      configuredAccess?.runtime.skills.ready ??
      skillsInventory.filter((skill) => skill.status === "ready").length,
    disabled:
      configuredAccess?.runtime.skills.disabled ??
      skillsInventory.filter((skill) => skill.status === "disabled").length,
    blocked:
      configuredAccess?.runtime.skills.blocked ??
      skillsInventory.filter((skill) => skill.status === "blocked").length,
    missing:
      configuredAccess?.runtime.skills.missing ??
      skillsInventory.filter((skill) => skill.status === "missing").length,
  };

  const capabilityInventory = configuredAccess?.capabilities || [];
  const runtimeCommands = (configuredAccess?.runtime.commands || []).map((cmd) => ({
    id: cmd.id,
    ok: cmd.ok,
    durationMs: cmd.durationMs,
  }));
  const inventoryCollectedAt = configuredAccess?.collectedAt ? new Date(configuredAccess.collectedAt) : null;
  const configPath = configuredAccess?.configPath || null;

  const executions = recentTraceRows.map((row) => ({
    executionId: row.traceId,
    triggerType: mapTriggerType(row.sourceType),
    triggerSource: row.openclawSessionKey || row.rootExecutionId || row.traceId,
    triggerRef: row.rootExecutionId || undefined,
    outcome: mapExecutionOutcome(row.status),
    startedAt: row.startedAt.toISOString(),
    durationMs: row.durationMs ?? undefined,
    toolCalls: row.spanCount ?? 0,
    domainsTouched: 0,
    errors: row.errorCount || 0,
    alertsRaised: row.blockCount || 0,
    parentExecutionId: undefined,
  }));
  const overviewExecutions = recentTraceRows.slice(0, 5).map((row) => ({
    traceId: row.traceId,
    triggerType: mapTriggerType(row.sourceType),
    status: mapExecutionOutcome(row.status),
    durationMs: row.durationMs ?? undefined,
    startedAt: row.startedAt.toISOString(),
  }));
  const online = Date.now() - agent.lastSeenAt.getTime() <= 10 * 60 * 1000;
  const host = configuredAccess?.hostName || runtimeMeta.hostName || latestSourceEvent?.sourceHost || "-";
  const os = [
    configuredAccess?.osPlatform || runtimeMeta.osPlatform,
    configuredAccess?.osRelease || runtimeMeta.osRelease,
    configuredAccess?.osArch || runtimeMeta.osArch,
  ]
    .filter(Boolean)
    .join(" ");
  const encodedAgentKey = encodeURIComponent(agent.agentKey);
  const tabParam = typeof query.tab === "string" ? query.tab.trim().toLowerCase() : "overview";
  const normalizedTab = tabParam === "activity" ? "timeline" : tabParam;
  const activeTab: AgentTabKey = AGENT_TABS.some((tab) => tab.key === normalizedTab)
    ? (normalizedTab as AgentTabKey)
    : "overview";

  return (
    <AppShell
      activeNav="agents"
      title={agent.displayName || agent.reportedName || "Agent dashboard"}
      subtitle="Agent console"
    >
      <ConsoleHeader
        agentKey={agent.agentKey}
        displayName={agent.displayName || agent.reportedName || agent.agentInstanceId || "Agent"}
        policyProfile={agent.policyProfile}
        online={online}
        host={host}
        os={os || "-"}
        sourceIp={latestSourceEvent?.sourceIp || "-"}
        lastSeen={fmt(agent.lastSeenAt)}
      />

      <TabNav activeTab={activeTab} baseHref={`/agents/${encodedAgentKey}`} />

      {activeTab === "overview" ? (
        <OverviewTab
          agentKey={agent.agentKey}
          events24h={events24h}
          traces24h={traces24h}
          policyBlocks24h={policyBlocks24h}
          alerts24h={alerts24h}
          errors24h={errors24h}
          domains={domainInventory}
          channels={channelInventory}
          plugins={pluginInventory}
          skills={skillsInventory}
          pluginSummary={pluginSummary}
          skillsSummary={skillsSummary}
          recentExecutions={overviewExecutions}
          capabilities={capabilityInventory}
          inventoryCollectedAt={inventoryCollectedAt}
          configPath={configPath}
          runtimeCommands={runtimeCommands}
        />
      ) : null}

      {activeTab === "timeline" ? (
        <TimelineTab executions={executions} />
      ) : null}

      {activeTab === "tools" ? (
        <ToolsTab
          agentKey={agent.agentKey}
          tools={toolInventory}
          skills={skillsInventory}
          plugins={pluginInventory}
        />
      ) : null}

      {activeTab === "policy" ? (
        <PolicyTab
          agentKey={agent.agentKey}
          policyProfile={agent.policyProfile}
          globalIntentPolicy={globalIntentPolicy}
          agentIntentPolicy={agentIntentPolicy}
          rules={rules}
          updateAgentAction={updateAgentAction}
          createScopedRuleAction={createScopedRuleAction}
          deleteScopedRuleAction={deleteScopedRuleAction}
        />
      ) : null}

      {activeTab === "settings" ? (
        <SettingsTab
          agentKey={agent.agentKey}
          displayName={agent.displayName || ""}
          notes={agent.notes || ""}
          policyProfile={agent.policyProfile}
          updateAgentAction={updateAgentAction}
          deleteAgentAction={deleteAgentAction}
        />
      ) : null}
    </AppShell>
  );
}
