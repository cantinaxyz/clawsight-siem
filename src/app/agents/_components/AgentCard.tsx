/**
 * @fileoverview ClawSight SIEM module: platform/src/app/agents/_components/AgentCard.tsx.
 */
import Link from "next/link";
import { Bell, CircleCheck, CircleDashed, ShieldAlert, Workflow } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";

type AgentCardProps = {
  href: string;
  displayName: string;
  description: string;
  agentKey: string;
  online: boolean;
  events24h: number;
  policyBlocks24h: number;
  alerts24h: number;
  channelsCount: number;
  skillsCount: number;
  pluginsCount: number;
  host: string;
  os: string;
  sourceIp: string;
  lastSeenLabel: string;
};

function StatusPill({ online }: { online: boolean }) {
  if (online) {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-0.5 text-xs font-medium text-emerald-300">
        <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
        Online
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-secondary px-2.5 py-0.5 text-xs font-medium text-secondary-foreground">
      <span className="h-1.5 w-1.5 rounded-full bg-muted-foreground" />
      Offline
    </span>
  );
}

function Metric({
  icon,
  label,
  value,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
}) {
  return (
    <div className="px-1 py-1">
      <div className="mb-1 flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-muted-foreground">
        {icon}
        <span>{label}</span>
      </div>
      <div className="text-sm font-semibold tabular-nums text-foreground">{value.toLocaleString()}</div>
    </div>
  );
}

export default function AgentCard({
  href,
  displayName,
  description,
  agentKey: _agentKey,
  online,
  events24h,
  policyBlocks24h,
  alerts24h,
  channelsCount,
  skillsCount,
  pluginsCount,
  host: _host,
  os,
  sourceIp,
  lastSeenLabel,
}: AgentCardProps) {
  const lastSeenValue = lastSeenLabel.replace(/^Last seen\s+/i, "");

  return (
    <Link href={href} className="group block">
      <Card className="h-full border-border/60 bg-card/70 transition-all duration-200 group-hover:-translate-y-0.5 group-hover:border-primary/30 group-hover:shadow-xl group-hover:shadow-primary/5">
        <CardContent className="space-y-4 p-5">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm font-semibold text-foreground">{displayName}</p>
              <p className="mt-1 line-clamp-2 text-xs leading-relaxed text-muted-foreground">{description}</p>
              <p className="mt-1 truncate text-[11px] text-muted-foreground">
                <span className="text-foreground">{os || "-"}</span>
                <span> · </span>
                <span className="font-mono text-foreground">{sourceIp || "-"}</span>
              </p>
            </div>
            <div className="flex shrink-0 items-center gap-1.5">
              <StatusPill online={online} />
            </div>
          </div>

          <div className="grid grid-cols-3 gap-2 rounded-xl bg-secondary/35 p-2.5">
            <Metric
              icon={<Workflow className="h-3 w-3 text-primary" />}
              label="Events"
              value={events24h}
            />
            <Metric
              icon={<ShieldAlert className="h-3 w-3 text-amber-400" />}
              label="Policy blocks"
              value={policyBlocks24h}
            />
            <Metric
              icon={<Bell className="h-3 w-3 text-rose-400" />}
              label="Alerts"
              value={alerts24h}
            />
          </div>

          <div className="border-t border-border/60 pt-3 text-xs">
            <div className="flex items-center justify-between gap-3">
              <span className="truncate font-medium text-foreground">{lastSeenValue}</span>
              <span className="truncate font-medium text-foreground">
                {channelsCount} channels · {skillsCount} skills · {pluginsCount} plugins
              </span>
            </div>
          </div>
        </CardContent>
      </Card>
    </Link>
  );
}
