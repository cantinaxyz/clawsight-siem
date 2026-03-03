/**
 * @fileoverview ClawSight SIEM module: platform/src/app/events/page.tsx.
 */
import Link from "next/link";
import { Search, X } from "lucide-react";
import AppShell from "@/components/app-shell";
import TelemetryEventStream from "@/components/telemetry-event-stream";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { buildManagedAgentEventWhere } from "@/lib/agents/filter";
import { discoverManagedAgents } from "@/lib/agents/discovery";
import { listManagedAgents } from "@/lib/agents/repository";
import { prisma } from "@/lib/prisma";
import { serializeTelemetryEvent } from "@/lib/telemetry-event-query";

type SearchParams = {
  category?: string;
  outcome?: string;
  policyRuleId?: string;
  requestId?: string;
  agentKey?: string;
  q?: string;
  search?: string;
  limit?: string;
};

function buildEventWhere(searchParams: SearchParams) {
  const where: Record<string, unknown> = {};
  if (searchParams.category) where.category = searchParams.category;
  if (searchParams.outcome) where.outcome = searchParams.outcome;
  if (searchParams.policyRuleId) where.policyRuleId = searchParams.policyRuleId;
  if (searchParams.agentKey) {
    const agentWhere = buildManagedAgentEventWhere(searchParams.agentKey);
    if (agentWhere) {
      where.AND = [...(Array.isArray(where.AND) ? where.AND : []), agentWhere];
    }
  }
  if (searchParams.requestId) where.requestId = searchParams.requestId;
  const searchTerm = searchParams.q || searchParams.search;
  if (searchTerm) {
    const needle = searchTerm.toLowerCase();
    where.OR = [
      { action: { contains: needle, mode: "insensitive" } },
      { category: { contains: needle, mode: "insensitive" } },
      { outcome: { contains: needle, mode: "insensitive" } },
      { outcomeReason: { contains: needle, mode: "insensitive" } },
      { policyRuleId: { contains: needle, mode: "insensitive" } },
      { openclawToolName: { contains: needle, mode: "insensitive" } },
      { agentName: { contains: needle, mode: "insensitive" } },
    ];
  }
  return where;
}

export default async function EventsPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const params = await searchParams;
  await discoverManagedAgents(200);
  const managedAgents = await listManagedAgents({ limit: 300 });
  const safeLimit = Math.min(Math.max(Number(params.limit) || 200, 20), 500);
  const where = buildEventWhere(params);
  const [events, totalEvents] = await Promise.all([
    prisma.telemetryEvent.findMany({
      where,
      take: safeLimit,
      orderBy: { ts: "desc" },
    }),
    prisma.telemetryEvent.count({ where }),
  ]);

  const streamFilters = {
    category: params.category?.trim(),
    outcome: params.outcome?.trim(),
    policyRuleId: params.policyRuleId?.trim(),
    requestId: params.requestId?.trim(),
    agentKey: params.agentKey?.trim(),
    search: (params.q || params.search || "").trim(),
  };
  const serializedEvents = events.map(serializeTelemetryEvent);
  const streamKey = `events:${streamFilters.category ?? ""}|${streamFilters.outcome ?? ""}|${streamFilters.policyRuleId ?? ""}|${streamFilters.requestId ?? ""}|${streamFilters.agentKey ?? ""}|${streamFilters.search ?? ""}|${safeLimit}`;
  const hasActiveFilters = Boolean(
    params.q ||
      params.search ||
      params.category ||
      params.outcome ||
      params.policyRuleId ||
      params.requestId ||
      params.agentKey ||
      params.limit,
  );

  return (
    <AppShell
      activeNav="events"
      title="Event Stream"
      subtitle="Live telemetry from OpenClaw agents with server-sent event updates"
    >
      <div className="flex flex-col gap-6">
        <form method="get" className="rounded-xl border border-border bg-card p-4">
          <div className="flex flex-col gap-4">
            <div className="flex flex-wrap items-center gap-3">
              <div className="relative min-w-[320px] max-w-xl flex-1">
                <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  name="q"
                  defaultValue={params.q ?? ""}
                  placeholder="Search by category, action, outcome, rule, tool..."
                  className="h-9 pl-9"
                />
              </div>

              <select
                name="agentKey"
                defaultValue={params.agentKey ?? ""}
                className="h-9 min-w-[220px] rounded-md border border-border bg-card px-3 text-sm text-foreground"
              >
                <option value="">All agents</option>
                {managedAgents.map((agent) => (
                  <option key={agent.agentKey} value={agent.agentKey}>
                    {agent.displayName || agent.reportedName || agent.agentInstanceId || agent.agentKey}
                  </option>
                ))}
              </select>

              <div className="ml-auto flex items-center gap-2">
                <Button type="submit" size="sm" className="h-9">
                  Apply
                </Button>
                <Button variant="outline" size="sm" asChild className="h-9">
                  <Link href="/events">Reset</Link>
                </Button>
                {hasActiveFilters ? (
                  <Button variant="ghost" size="sm" asChild className="h-9 px-2.5 text-xs text-muted-foreground">
                    <Link href="/events" className="inline-flex items-center gap-1">
                      <X className="h-3 w-3" />
                      Clear
                    </Link>
                  </Button>
                ) : null}
              </div>
            </div>

            <div className="grid grid-cols-1 gap-3 md:grid-cols-[1fr_1fr_140px]">
              <select
                name="category"
                defaultValue={params.category ?? ""}
                className="h-9 rounded-md border border-border bg-card px-3 text-sm text-foreground"
              >
                <option value="">All categories</option>
                <option value="tool">tool</option>
                <option value="policy">policy</option>
                <option value="session">session</option>
                <option value="message">message</option>
                <option value="agent">agent</option>
                <option value="gateway">gateway</option>
                <option value="diagnostic">diagnostic</option>
                <option value="log">log</option>
              </select>

              <select
                name="outcome"
                defaultValue={params.outcome ?? ""}
                className="h-9 rounded-md border border-border bg-card px-3 text-sm text-foreground"
              >
                <option value="">All outcomes</option>
                <option value="allow">allow</option>
                <option value="block">block</option>
                <option value="modify">modify</option>
                <option value="error">error</option>
                <option value="unknown">unknown</option>
              </select>

              <Input name="limit" defaultValue={String(safeLimit)} placeholder="Limit" className="h-9" />
            </div>

            <details className="group rounded-md border border-border/70 bg-muted/20 p-3">
              <summary className="cursor-pointer text-xs font-medium uppercase tracking-wider text-muted-foreground">
                Advanced filters
              </summary>
              <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-3">
                <Input name="policyRuleId" defaultValue={params.policyRuleId ?? ""} placeholder="Policy Rule ID" className="h-9" />
                <Input name="requestId" defaultValue={params.requestId ?? ""} placeholder="Request ID" className="h-9" />
              </div>
            </details>

            <p className="text-xs text-muted-foreground">
              Ingest endpoints: <code>/api/telemetry/ingest</code> and <code>/v1/telemetry/ingest</code>
            </p>
          </div>
        </form>

        <div className="rounded-xl border border-border bg-card p-4">
          <TelemetryEventStream
            key={streamKey}
            initialEvents={serializedEvents}
            total={totalEvents}
            limit={safeLimit}
            filters={streamFilters}
          />
        </div>
      </div>
    </AppShell>
  );
}
