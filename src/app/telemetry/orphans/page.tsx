/**
 * @fileoverview ClawSight SIEM module: platform/src/app/telemetry/orphans/page.tsx.
 */
import Link from "next/link";
import { Prisma } from "@prisma/client";
import AppShell from "@/components/app-shell";
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
import {
  parsePositiveInt,
  serializeTraceOrphanRecord,
  type TraceOrphanRecord,
} from "@/lib/traces/query";

type SearchParams = {
  reason?: string;
  q?: string;
  search?: string;
  limit?: string;
};

function isMissingTraceOrphanTableError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  const message = err.message.toLowerCase();
  return message.includes("does not exist") && message.includes("traceorphan");
}

function formatTime(ts: number | null): string {
  if (!ts) return "-";
  const date = new Date(ts);
  if (!Number.isFinite(date.getTime())) return "-";
  return date.toLocaleString("en-US", {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

export default async function OrphanTelemetryPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const params = await searchParams;
  const reason = params.reason?.trim() || "";
  const search = (params.search || params.q || "").trim();
  const limit = parsePositiveInt(params.limit || null, 100, 500);

  const conditions: Prisma.Sql[] = [];
  if (reason) {
    conditions.push(Prisma.sql`"reason" = ${reason}`);
  }
  if (search) {
    const needle = `%${search}%`;
    conditions.push(
      Prisma.sql`(
        COALESCE("eventExternalId", '') ILIKE ${needle}
        OR COALESCE("requestId", '') ILIKE ${needle}
        OR COALESCE("rootExecutionId", '') ILIKE ${needle}
        OR COALESCE("rootMessageId", '') ILIKE ${needle}
        OR COALESCE("traceHint", '') ILIKE ${needle}
        OR COALESCE("openclawSessionKey", '') ILIKE ${needle}
      )`,
    );
  }

  const whereClause =
    conditions.length > 0 ? Prisma.sql`WHERE ${Prisma.join(conditions, " AND ")}` : Prisma.empty;

  let rows: TraceOrphanRecord[] = [];
  let total = 0;
  try {
    const [queryRows, countRows] = await Promise.all([
      prisma.$queryRaw<TraceOrphanRecord[]>(Prisma.sql`
        SELECT
          "id",
          "eventExternalId",
          "eventTs",
          "eventCategory",
          "eventAction",
          "reason",
          "traceHint",
          "requestId",
          "rootExecutionId",
          "rootMessageId",
          "openclawSessionKey",
          "payload",
          "createdAt",
          "updatedAt"
        FROM "TraceOrphan"
        ${whereClause}
        ORDER BY "createdAt" DESC
        LIMIT ${limit}
      `),
      prisma.$queryRaw<Array<{ count: bigint }>>(Prisma.sql`
        SELECT COUNT(*)::bigint AS "count"
        FROM "TraceOrphan"
        ${whereClause}
      `),
    ]);
    rows = queryRows;
    total = Number(countRows[0]?.count ?? 0n);
  } catch (err) {
    if (!isMissingTraceOrphanTableError(err)) {
      throw err;
    }
  }

  const items = rows.map(serializeTraceOrphanRecord);

  return (
    <AppShell
      activeNav="traces"
      title="Orphan telemetry"
      subtitle="Events that could not be correlated to a valid trace"
    >
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Filter orphan records</CardTitle>
          <CardDescription>Inspect unmatched events without polluting trace timelines.</CardDescription>
        </CardHeader>
        <CardContent>
          <form method="get" className="grid grid-cols-1 gap-3 md:grid-cols-5">
            <Input name="q" defaultValue={search} placeholder="Search orphan fields" className="md:col-span-2" />
            <Input name="reason" defaultValue={reason} placeholder="Reason" />
            <Input name="limit" defaultValue={String(limit)} placeholder="Limit" />
            <div className="flex items-center gap-2">
              <Button type="submit" size="sm">
                Apply
              </Button>
              <Button variant="outline" size="sm" asChild>
                <Link href="/telemetry/orphans">Reset</Link>
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Recent orphan telemetry</CardTitle>
          <CardDescription>
            Showing {items.length} of {total}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Time</TableHead>
                <TableHead>Reason</TableHead>
                <TableHead>Category/Action</TableHead>
                <TableHead>Request</TableHead>
                <TableHead>Session</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-sm text-muted-foreground">
                    No orphan telemetry rows.
                  </TableCell>
                </TableRow>
              ) : (
                items.map((orphan) => (
                  <TableRow key={orphan.id}>
                    <TableCell className="text-xs text-muted-foreground">{formatTime(orphan.eventTs)}</TableCell>
                    <TableCell className="text-sm">{orphan.reason}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {orphan.eventCategory || "-"}.{orphan.eventAction || "-"}
                    </TableCell>
                    <TableCell className="max-w-[220px] truncate text-xs text-muted-foreground">
                      {orphan.requestId || orphan.rootExecutionId || orphan.rootMessageId || "-"}
                    </TableCell>
                    <TableCell className="max-w-[220px] truncate text-xs text-muted-foreground">
                      {orphan.openclawSessionKey || orphan.traceHint || "-"}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </AppShell>
  );
}
