/**
 * @fileoverview ClawSight SIEM module: platform/src/app/executions/[executionId]/page.tsx.
 */
import Link from "next/link";
import AppShell from "@/components/app-shell";
import ExecutionTraceDetailClient from "@/app/executions/[executionId]/ExecutionTraceDetailClient";

type ParamsInput = { executionId: string };

async function resolveParams(params: ParamsInput | Promise<ParamsInput>): Promise<ParamsInput> {
  return Promise.resolve(params);
}

export default async function ExecutionDetailPage({
  params,
}: {
  params: ParamsInput | Promise<ParamsInput>;
}) {
  const resolved = await resolveParams(params);
  const executionId = decodeURIComponent(String(resolved.executionId || "").trim());

  return (
    <AppShell
      activeNav="traces"
      title="Execution details"
      subtitle="Full timeline and trace detail for a single execution"
    >
      <div className="flex items-center justify-between">
        <Link
          href="/executions"
          className="inline-flex items-center rounded-md border border-border bg-secondary/60 px-2.5 py-1 text-xs text-muted-foreground hover:text-foreground"
        >
          Back to executions
        </Link>
        <p className="truncate font-mono text-xs text-muted-foreground">{executionId}</p>
      </div>
      <ExecutionTraceDetailClient executionId={executionId} />
    </AppShell>
  );
}
