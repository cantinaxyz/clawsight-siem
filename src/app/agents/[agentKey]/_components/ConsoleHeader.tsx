/**
 * @fileoverview ClawSight SIEM module: platform/src/app/agents/[agentKey]/_components/ConsoleHeader.tsx.
 */
import Link from "next/link";
import { ArrowLeft, ExternalLink, Server } from "lucide-react";
import { Button } from "@/components/ui/button";

type ConsoleHeaderProps = {
  agentKey: string;
  displayName: string;
  policyProfile: string;
  online: boolean;
  host: string;
  os: string;
  sourceIp: string;
  lastSeen: string;
};

function StatusPill({ online }: { online: boolean }) {
  if (online) {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-0.5 text-xs font-medium text-emerald-400">
        <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
        Online
      </span>
    );
  }

  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-rose-500/30 bg-rose-500/10 px-2.5 py-0.5 text-xs font-medium text-rose-400">
      <span className="h-1.5 w-1.5 rounded-full bg-rose-400" />
      Offline
    </span>
  );
}

export default function ConsoleHeader({
  agentKey,
  displayName,
  policyProfile,
  online,
  host,
  os,
  sourceIp,
  lastSeen,
}: ConsoleHeaderProps) {
  const encoded = encodeURIComponent(agentKey);

  return (
    <div className="sticky top-[70px] z-10 border-b border-border bg-background/95 px-4 py-5 backdrop-blur supports-[backdrop-filter]:bg-background/80 md:px-6">
      <div className="flex items-start justify-between gap-4">
        <div className="flex min-w-0 items-start gap-3">
          <Button variant="ghost" size="icon" className="mt-0.5 h-8 w-8 shrink-0" asChild>
            <Link href="/agents" aria-label="Back to agents">
              <ArrowLeft className="h-4 w-4" />
            </Link>
          </Button>

          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2.5">
              <h2 className="truncate text-2xl font-bold tracking-tight text-foreground">{displayName}</h2>
              <StatusPill online={online} />
              <span className="inline-flex rounded-md border border-muted-foreground/30 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                {policyProfile}
              </span>
            </div>

            <div className="mt-1.5 flex items-center gap-2 text-xs text-muted-foreground">
              <span className="truncate font-mono">{agentKey}</span>
            </div>

            <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
              <Server className="h-3 w-3 text-muted-foreground/60" />
              <span className="flex items-center gap-1">
                Host <span className="font-mono text-foreground">{host || "-"}</span>
              </span>
              <span className="text-border">|</span>
              <span className="flex items-center gap-1">
                OS <span className="font-mono text-foreground">{os || "-"}</span>
              </span>
              <span className="text-border">|</span>
              <span className="flex items-center gap-1">
                IP <span className="font-mono text-foreground">{sourceIp || "-"}</span>
              </span>
              <span className="text-border">|</span>
              <span>
                Last seen <span className="text-foreground">{lastSeen}</span>
              </span>
            </div>
          </div>
        </div>

        <div className="flex shrink-0 items-center gap-2">
          <Button size="sm" asChild>
            <Link href={`/executions?agentKey=${encoded}`}>
              <ExternalLink className="mr-1.5 h-3.5 w-3.5" />
              View Executions
            </Link>
          </Button>
          <Button variant="secondary" size="sm" asChild>
            <Link href={`/events?agentKey=${encoded}`}>
              <ExternalLink className="mr-1.5 h-3.5 w-3.5" />
              View Events
            </Link>
          </Button>
        </div>
      </div>
    </div>
  );
}
