/**
 * @fileoverview ClawSight SIEM module: platform/src/app/page.tsx.
 */
import AppShell from "@/components/app-shell";
import { ActivityBreakdownPie } from "@/components/dashboard/activity-breakdown-pie";
import { ActivityChart, type ActivityChartPoint } from "@/components/dashboard/activity-chart";
import { DashboardLiveRefresh } from "@/components/dashboard/dashboard-live-refresh";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { prisma } from "@/lib/prisma";

export const dynamic = "force-dynamic";
export const revalidate = 0;

type TopUrlRow = { value: string; hits: bigint };
type DomainIpRow = { domain: string; ip: string };

function isMissingDomainIpTableError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  const message = err.message.toLowerCase();
  return message.includes("domainipresolution") && message.includes("does not exist");
}

function hourStart(date: Date): Date {
  const clone = new Date(date);
  clone.setMinutes(0, 0, 0);
  return clone;
}

function hourKey(date: Date): string {
  return [
    date.getFullYear(),
    date.getMonth() + 1,
    date.getDate(),
    date.getHours(),
  ].join("-");
}

function hourLabel(date: Date): string {
  return date.toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

function buildLastHourBuckets(hours = 24): Date[] {
  const end = hourStart(new Date());
  const buckets: Date[] = [];
  for (let index = hours - 1; index >= 0; index -= 1) {
    const point = new Date(end);
    point.setHours(end.getHours() - index);
    buckets.push(point);
  }
  return buckets;
}

function extractDomain(raw: string): string | null {
  const value = String(raw || "").trim();
  if (!value) return null;
  try {
    return new URL(value).hostname.toLowerCase();
  } catch {
    try {
      return new URL(`https://${value}`).hostname.toLowerCase();
    } catch {
      return null;
    }
  }
}

async function getLatestDomainIpMap(since: Date): Promise<Map<string, string>> {
  try {
    const rows = await prisma.$queryRaw<DomainIpRow[]>`
      SELECT DISTINCT ON ("domain") "domain", "ip"
      FROM "DomainIpResolution"
      WHERE "lastSeenAt" >= ${since}
      ORDER BY "domain", "lastSeenAt" DESC
    `;
    return new Map(rows.map((row) => [String(row.domain || "").toLowerCase(), String(row.ip || "-")]));
  } catch (err) {
    if (isMissingDomainIpTableError(err)) return new Map();
    throw err;
  }
}

export default async function DashboardPage() {
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);

  const [
    events24h,
    blocks24h,
    alerts24h,
    registeredAgents,
    recentEvents,
    topUrlRows,
    domainIpMap,
  ] = await Promise.all([
    prisma.telemetryEvent.count({ where: { ts: { gte: since } } }),
    prisma.telemetryEvent.count({ where: { ts: { gte: since }, outcome: "block" } }),
    prisma.threatAlert.count({ where: { ts: { gte: since }, alertModel: "execution_v2" } }),
    prisma.managedAgent.count(),
    prisma.telemetryEvent.findMany({
      where: { ts: { gte: since } },
      orderBy: { ts: "asc" },
      take: 5000,
      select: {
        ts: true,
        category: true,
      },
    }),
    prisma.$queryRaw<TopUrlRow[]>`
      SELECT "value", COUNT(*)::bigint AS "hits"
      FROM "TelemetryObservable"
      WHERE "kind" = 'url' AND "eventTs" >= ${since}
      GROUP BY "value"
      ORDER BY COUNT(*) DESC
      LIMIT 12
    `,
    getLatestDomainIpMap(since),
  ]);

  const buckets = buildLastHourBuckets(24);
  const activityMap = new Map<string, number>();
  for (const bucket of buckets) {
    activityMap.set(hourKey(bucket), 0);
  }

  const categoryCounts = new Map<string, number>();
  for (const event of recentEvents) {
    const key = hourKey(hourStart(event.ts));
    if (activityMap.has(key)) activityMap.set(key, (activityMap.get(key) ?? 0) + 1);
    categoryCounts.set(event.category, (categoryCounts.get(event.category) ?? 0) + 1);
  }

  const activitySeries: ActivityChartPoint[] = buckets.map((bucket) => ({
    time: hourLabel(bucket),
    events: activityMap.get(hourKey(bucket)) ?? 0,
  }));

  const topCategories = [...categoryCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);
  const maxCategoryCount = Math.max(topCategories[0]?.[1] ?? 1, 1);

  const topUrls = topUrlRows.map((row) => {
    const url = row.value;
    const domain = extractDomain(url);
    return {
      url,
      ip: (domain ? domainIpMap.get(domain) : null) || "-",
      hits: Number(row.hits),
    };
  });

  return (
    <AppShell
      activeNav="dashboard"
      title="Dashboard"
      subtitle={`Operational telemetry overview (last 24 hours) · Registered agents: ${registeredAgents}`}
    >
      <DashboardLiveRefresh />
      <div className="flex flex-col gap-6">
        <ActivityChart data={activitySeries} />

        <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
          <ActivityBreakdownPie
            events={events24h}
            blocks={blocks24h}
            alerts={alerts24h}
          />

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Top Called URLs</CardTitle>
              <CardDescription>URL to resolved IP mapping (24h)</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {topUrls.length === 0 ? (
                <p className="text-sm text-muted-foreground">No URL observables yet.</p>
              ) : (
                topUrls.map((row) => (
                  <div key={row.url} className="flex items-start justify-between gap-3 text-sm">
                    <div className="min-w-0">
                      <div className="truncate text-foreground">{row.url}</div>
                      <div className="truncate text-xs text-muted-foreground">{row.ip}</div>
                    </div>
                    <span className="shrink-0 tabular-nums text-muted-foreground">{row.hits}</span>
                  </div>
                ))
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Top Telemetry Categories</CardTitle>
              <CardDescription>Most frequent categories in the last 24 hours</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {topCategories.length === 0 ? (
                <p className="text-sm text-muted-foreground">No category data yet.</p>
              ) : (
                topCategories.map(([category, count]) => (
                  <div key={category} className="space-y-1">
                    <div className="flex items-center justify-between text-sm">
                      <span className="font-medium text-foreground">{category}</span>
                      <span className="tabular-nums text-muted-foreground">{count}</span>
                    </div>
                    <div className="h-1.5 overflow-hidden rounded-full bg-muted">
                      <div
                        className="h-full rounded-full bg-primary"
                        style={{ width: `${Math.max(2, Math.round((count / maxCategoryCount) * 100))}%` }}
                      />
                    </div>
                  </div>
                ))
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </AppShell>
  );
}
