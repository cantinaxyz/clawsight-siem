/**
 * @fileoverview ClawSight SIEM module: platform/src/app/alerts/[id]/page.tsx.
 */
import Link from "next/link";
import { revalidatePath } from "next/cache";
import { notFound, redirect } from "next/navigation";
import { Prisma } from "@prisma/client";
import AppShell from "@/components/app-shell";
import {
  canTransitionAlertStatus,
  normalizeAlertClassification,
  normalizeAlertStatus,
  requiresResolutionNote,
  type AlertStatus,
} from "@/lib/alerts/lifecycle";
import { prisma } from "@/lib/prisma";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

type PageProps = {
  params: Promise<{ id: string }>;
};

type IntentBaselineRow = {
  executionKey: string;
  rootExecutionId: string;
  taskBoundary: string | null;
  expectedScopes: unknown;
  expectedDomains: unknown;
  driftScore: number;
  extractionMethod: string | null;
  status: string | null;
  updatedAt: Date;
};

type ToolAggRow = {
  toolName: string;
  calls: number;
  errors: number;
};

type DomainAggRow = {
  domain: string;
  calls: number;
};

function parseId(value: string): number | null {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) return null;
  return parsed;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function readDetailString(details: unknown, key: string): string | null {
  const rec = asRecord(details);
  if (!rec) return null;
  const value = rec[key];
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed || null;
}

function toStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const out: string[] = [];
  for (const item of value) {
    const raw = String(item || "").trim();
    if (raw) out.push(raw);
  }
  return out;
}

function severityClass(value: string): string {
  switch (value) {
    case "critical":
      return "border-destructive/40 bg-destructive/10 text-destructive";
    case "high":
      return "border-orange-500/30 bg-orange-500/10 text-orange-300";
    case "medium":
      return "border-yellow-500/30 bg-yellow-500/10 text-yellow-300";
    case "low":
      return "border-blue-500/30 bg-blue-500/10 text-blue-300";
    default:
      return "border-border bg-secondary text-secondary-foreground";
  }
}

function statusClass(value: string): string {
  switch (value) {
    case "open":
      return "border-destructive/40 bg-destructive/10 text-destructive";
    case "acknowledged":
      return "border-blue-500/30 bg-blue-500/10 text-blue-300";
    case "resolved":
      return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
    case "false_positive":
      return "border-zinc-500/30 bg-zinc-500/10 text-zinc-300";
    default:
      return "border-border bg-secondary text-secondary-foreground";
  }
}

function alertTypeClass(value: string): string {
  switch (value) {
    case "intent_drift":
      return "border-fuchsia-500/30 bg-fuchsia-500/10 text-fuchsia-300";
    case "policy_block":
      return "border-yellow-500/30 bg-yellow-500/10 text-yellow-300";
    case "tool_output_injection":
      return "border-red-500/30 bg-red-500/10 text-red-300";
    case "execution_error":
      return "border-orange-500/30 bg-orange-500/10 text-orange-300";
    default:
      return "border-border bg-secondary text-secondary-foreground";
  }
}

async function transitionAction(formData: FormData) {
  "use server";

  const idValue = formData.get("id");
  const nextValue = formData.get("nextStatus");
  const returnToValue = formData.get("returnTo");
  const id = typeof idValue === "string" ? parseId(idValue) : null;
  const nextStatus = normalizeAlertStatus(nextValue);
  const returnTo = typeof returnToValue === "string" && returnToValue.startsWith("/alerts/") ? returnToValue : "/alerts";

  if (!id || !nextStatus) {
    redirect(returnTo);
  }

  const alert = await prisma.threatAlert.findUnique({ where: { id } });
  if (!alert) {
    redirect("/alerts");
  }

  const currentStatus = normalizeAlertStatus(alert.status) || "open";
  if (!canTransitionAlertStatus(currentStatus, nextStatus as AlertStatus)) {
    redirect(returnTo);
  }

  const now = new Date();
  const shouldOpen = nextStatus === "open";
  const shouldAck = nextStatus === "acknowledged";
  const isTerminal = nextStatus === "resolved" || nextStatus === "false_positive";
  await prisma.$executeRaw`
    UPDATE "ThreatAlert"
    SET
      "status" = ${nextStatus},
      "ackAt" = CASE
        WHEN ${shouldAck} THEN COALESCE("ackAt", ${now})
        WHEN ${shouldOpen} THEN NULL
        ELSE "ackAt"
      END,
      "resolvedAt" = CASE
        WHEN ${isTerminal} THEN ${now}
        WHEN ${shouldOpen} THEN NULL
        ELSE "resolvedAt"
      END,
      "resolutionNote" = CASE WHEN ${shouldOpen} THEN NULL ELSE "resolutionNote" END,
      "updatedAt" = NOW()
    WHERE "id" = ${id}
  `;

  revalidatePath("/alerts");
  revalidatePath(returnTo);
  redirect(returnTo);
}

async function resolveAction(formData: FormData) {
  "use server";

  const idValue = formData.get("id");
  const returnToValue = formData.get("returnTo");
  const nextValue = formData.get("nextStatus");
  const noteValue = formData.get("resolutionNote");
  const classificationValue = formData.get("classification");

  const id = typeof idValue === "string" ? parseId(idValue) : null;
  const returnTo = typeof returnToValue === "string" && returnToValue.startsWith("/alerts/") ? returnToValue : "/alerts";
  const nextStatus = normalizeAlertStatus(nextValue);
  const note = typeof noteValue === "string" ? noteValue.trim() : "";
  const classification = normalizeAlertClassification(classificationValue);

  if (!id || !nextStatus) {
    redirect(returnTo);
  }

  const alert = await prisma.threatAlert.findUnique({ where: { id } });
  if (!alert) {
    redirect("/alerts");
  }

  const currentStatus = normalizeAlertStatus(alert.status) || "open";
  if (!canTransitionAlertStatus(currentStatus, nextStatus as AlertStatus)) {
    redirect(returnTo);
  }

  if (requiresResolutionNote(nextStatus as AlertStatus) && note.length < 8) {
    redirect(`${returnTo}?error=resolution-note-required`);
  }

  const alertMeta = alert as typeof alert & { classification?: string | null };
  const now = new Date();
  await prisma.$executeRaw`
    UPDATE "ThreatAlert"
    SET
      "status" = ${nextStatus},
      "ackAt" = COALESCE("ackAt", ${now}),
      "resolvedAt" = ${now},
      "resolutionNote" = ${note},
      "classification" = COALESCE(${classification ?? null}, ${alertMeta.classification ?? null}),
      "updatedAt" = NOW()
    WHERE "id" = ${id}
  `;

  revalidatePath("/alerts");
  revalidatePath(returnTo);
  redirect(returnTo);
}

export default async function AlertDetailPage({ params }: PageProps) {
  const route = await params;
  const alertId = parseId(route.id);
  if (!alertId) notFound();

  const alert = await prisma.threatAlert.findUnique({ where: { id: alertId } });
  if (!alert) notFound();
  const alertMeta = alert as typeof alert & {
    alertType?: string | null;
    triggerType?: string | null;
    executionId?: string | null;
    topTool?: string | null;
    topDomain?: string | null;
    driftScore?: number | null;
    classification?: string | null;
    resolutionNote?: string | null;
  };

  const executionId =
    alertMeta.executionId ||
    readDetailString(alert.details, "executionId") ||
    readDetailString(alert.details, "traceId") ||
    null;

  const [trace, traceSpans, intentBaselineRows, toolRows, domainRows] =
    await Promise.all([
      executionId
        ? prisma.trace.findUnique({ where: { traceId: executionId } })
        : Promise.resolve(null),
      executionId
        ? prisma.traceSpan.findMany({ where: { traceId: executionId }, orderBy: { ts: "asc" }, take: 500 })
        : Promise.resolve([]),
      executionId
        ? prisma.$queryRaw<Array<IntentBaselineRow>>(Prisma.sql`
            SELECT "executionKey", "rootExecutionId", "taskBoundary", "expectedScopes", "expectedDomains", "driftScore", "extractionMethod", "status", "updatedAt"
            FROM "ExecutionIntent"
            WHERE "executionKey" = ${executionId} OR "rootExecutionId" = ${executionId}
            ORDER BY "updatedAt" DESC
            LIMIT 1
          `)
        : Promise.resolve([]),
      executionId
        ? prisma.$queryRaw<Array<ToolAggRow>>(Prisma.sql`
            SELECT
              COALESCE(NULLIF("openclawToolName", ''), 'unknown') AS "toolName",
              COUNT(*)::int AS "calls",
              SUM(CASE WHEN LOWER(COALESCE("outcome", '')) = 'error' THEN 1 ELSE 0 END)::int AS "errors"
            FROM "TelemetryEvent"
            WHERE "category" = 'tool'
              AND ("traceId" = ${executionId} OR "rootExecutionId" = ${executionId})
            GROUP BY 1
            ORDER BY "calls" DESC
            LIMIT 25
          `)
        : Promise.resolve([]),
      executionId
        ? prisma.$queryRaw<Array<DomainAggRow>>(Prisma.sql`
            SELECT LOWER(o."value") AS "domain", COUNT(*)::int AS "calls"
            FROM "TelemetryObservable" o
            JOIN "TelemetryEvent" e ON e."id" = o."eventId"
            WHERE o."kind" = 'domain'
              AND e."category" = 'tool'
              AND (e."traceId" = ${executionId} OR e."rootExecutionId" = ${executionId})
            GROUP BY 1
            ORDER BY "calls" DESC
            LIMIT 20
          `)
        : Promise.resolve([]),
    ]);

  const baseline = intentBaselineRows[0] ?? null;
  const currentStatus = normalizeAlertStatus(alert.status) || "open";

  return (
    <AppShell
      activeNav="alerts"
      title={`Alert #${alert.id}`}
      subtitle="Investigate intent drift, tool behavior, policy decisions, and execution context"
    >
      <div className="flex flex-col gap-6">
        <div className="rounded-xl border border-border bg-card p-4">
          <div className="flex flex-wrap items-center gap-2">
            <Badge className={severityClass(alert.ruleSeverity)}>{alert.ruleSeverity}</Badge>
            <Badge className={statusClass(alert.status)}>{alert.status}</Badge>
            {alertMeta.alertType ? <Badge className={alertTypeClass(alertMeta.alertType)}>{alertMeta.alertType}</Badge> : null}
            {alertMeta.triggerType ? <Badge variant="outline">{alertMeta.triggerType}</Badge> : null}
            {alert.eventOutcome ? <Badge variant="outline">outcome:{alert.eventOutcome}</Badge> : null}
          </div>

          <div className="mt-3 grid grid-cols-1 gap-3 text-sm text-muted-foreground md:grid-cols-3">
            <div>
              <div className="text-xs uppercase tracking-wide">Rule</div>
              <div className="text-foreground">{alert.ruleName}</div>
            </div>
            <div>
              <div className="text-xs uppercase tracking-wide">Execution</div>
              <div className="font-mono text-xs text-foreground">{executionId || "-"}</div>
            </div>
            <div>
              <div className="text-xs uppercase tracking-wide">Request</div>
              <div className="font-mono text-xs text-foreground">{alert.requestId || "-"}</div>
            </div>
          </div>

          <div className="mt-3 flex flex-wrap items-center gap-2">
            {currentStatus === "open" ? (
              <form action={transitionAction}>
                <input type="hidden" name="id" value={alert.id} />
                <input type="hidden" name="nextStatus" value="acknowledged" />
                <input type="hidden" name="returnTo" value={`/alerts/${alert.id}`} />
                <Button type="submit" size="sm" variant="outline">ACK</Button>
              </form>
            ) : null}
            {currentStatus === "acknowledged" ? (
              <form action={transitionAction}>
                <input type="hidden" name="id" value={alert.id} />
                <input type="hidden" name="nextStatus" value="open" />
                <input type="hidden" name="returnTo" value={`/alerts/${alert.id}`} />
                <Button type="submit" size="sm" variant="outline">Unack</Button>
              </form>
            ) : null}
            {executionId ? (
              <Button asChild size="sm" variant="secondary">
                <Link href={`/executions?focusExecutionId=${encodeURIComponent(executionId)}`}>View execution</Link>
              </Button>
            ) : null}
            <Button asChild size="sm" variant="ghost">
              <Link href={`/events?requestId=${encodeURIComponent(alert.requestId || "")}`}>View events</Link>
            </Button>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <section className="rounded-xl border border-border bg-card p-4">
            <h2 className="text-sm font-semibold text-foreground">Execution context</h2>
            <div className="mt-3 space-y-2 text-sm text-muted-foreground">
              <div>
                Trigger: <span className="text-foreground">{alertMeta.triggerType || "-"}</span>
              </div>
              <div>
                Trace status: <span className="text-foreground">{trace?.status || "-"}</span>
              </div>
              <div>
                Drift score: <span className="text-foreground">{alertMeta.driftScore ?? baseline?.driftScore ?? "-"}</span>
              </div>
              <div>
                Top tool: <span className="text-foreground">{alertMeta.topTool || "-"}</span>
              </div>
              <div>
                Top domain: <span className="text-foreground">{alertMeta.topDomain || "-"}</span>
              </div>
              <div>
                Span count: <span className="text-foreground">{traceSpans.length}</span>
              </div>
            </div>
          </section>

          <section className="rounded-xl border border-border bg-card p-4">
            <h2 className="text-sm font-semibold text-foreground">Intent baseline</h2>
            {baseline ? (
              <div className="mt-3 space-y-2 text-sm text-muted-foreground">
                <div>
                  Boundary: <span className="text-foreground">{baseline.taskBoundary || "-"}</span>
                </div>
                <div>
                  Scopes: <span className="text-foreground">{toStringArray(baseline.expectedScopes).join(", ") || "-"}</span>
                </div>
                <div>
                  Domains: <span className="text-foreground">{toStringArray(baseline.expectedDomains).join(", ") || "-"}</span>
                </div>
                <div>
                  Method: <span className="text-foreground">{baseline.extractionMethod || "-"}</span>
                </div>
              </div>
            ) : (
              <p className="mt-3 text-sm text-muted-foreground">No execution intent baseline available for this alert.</p>
            )}
          </section>

          <section className="rounded-xl border border-border bg-card p-4">
            <h2 className="text-sm font-semibold text-foreground">Tool and domain review</h2>
            <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-2">
              <div>
                <div className="text-xs uppercase tracking-wide text-muted-foreground">Top tools</div>
                <div className="mt-2 space-y-1 text-sm">
                  {toolRows.length ? (
                    toolRows.map((row) => (
                      <div key={row.toolName} className="flex items-center justify-between rounded border border-border/70 px-2 py-1">
                        <span className="text-foreground">{row.toolName}</span>
                        <span className="text-muted-foreground">{row.calls} calls · {row.errors} errors</span>
                      </div>
                    ))
                  ) : (
                    <div className="text-muted-foreground">No tool activity.</div>
                  )}
                </div>
              </div>
              <div>
                <div className="text-xs uppercase tracking-wide text-muted-foreground">Domains touched</div>
                <div className="mt-2 space-y-1 text-sm">
                  {domainRows.length ? (
                    domainRows.map((row) => (
                      <div key={row.domain} className="flex items-center justify-between rounded border border-border/70 px-2 py-1">
                        <span className="text-foreground">{row.domain}</span>
                        <span className="text-muted-foreground">{row.calls}</span>
                      </div>
                    ))
                  ) : (
                    <div className="text-muted-foreground">No domain activity.</div>
                  )}
                </div>
              </div>
            </div>
          </section>

        </div>

        <section className="rounded-xl border border-border bg-card p-4">
          <h2 className="text-sm font-semibold text-foreground">Resolution</h2>
          <form action={resolveAction} className="mt-3 grid grid-cols-1 gap-3 lg:grid-cols-[180px_220px_1fr_auto]">
            <input type="hidden" name="id" value={alert.id} />
            <input type="hidden" name="returnTo" value={`/alerts/${alert.id}`} />

            <select
              name="nextStatus"
              defaultValue="resolved"
              className="h-9 rounded-md border border-border bg-card px-3 text-sm text-foreground"
            >
              <option value="resolved">resolved</option>
              <option value="false_positive">false_positive</option>
            </select>

            <select
              name="classification"
              defaultValue={alertMeta.classification || "benign_anomaly"}
              className="h-9 rounded-md border border-border bg-card px-3 text-sm text-foreground"
            >
              <option value="malicious_input">malicious_input</option>
              <option value="capability_abuse">capability_abuse</option>
              <option value="policy_misconfig">policy_misconfig</option>
              <option value="agent_bug">agent_bug</option>
              <option value="benign_anomaly">benign_anomaly</option>
            </select>

            <Input
              name="resolutionNote"
              defaultValue={alertMeta.resolutionNote || ""}
              placeholder="Resolution note (required, min 8 chars)"
              className="h-9"
            />

            <Button type="submit" size="sm" className="h-9">Save resolution</Button>
          </form>
          {alertMeta.resolutionNote ? (
            <p className="mt-2 text-xs text-muted-foreground">Last note: {alertMeta.resolutionNote}</p>
          ) : null}
        </section>
      </div>
    </AppShell>
  );
}
