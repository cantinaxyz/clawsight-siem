/**
 * @fileoverview ClawSight SIEM module: platform/src/components/trigger-badge.tsx.
 */
import { cn } from "@/lib/utils";
import type { ExecutionOutcome, TriggerType } from "@/lib/executions/types";
import {
  AlertCircle,
  Ban,
  CheckCircle2,
  Clock,
  Cpu,
  Link2,
  RotateCw,
  User,
  Webhook,
} from "lucide-react";

const triggerConfig: Record<
  TriggerType,
  {
    label: string;
    icon: typeof User;
    className: string;
  }
> = {
  user: {
    label: "User",
    icon: User,
    className: "border-blue-500/30 bg-blue-500/10 text-blue-300",
  },
  cron: {
    label: "Cron",
    icon: Clock,
    className: "border-violet-500/30 bg-violet-500/10 text-violet-300",
  },
  webhook: {
    label: "Webhook",
    icon: Webhook,
    className: "border-cyan-500/30 bg-cyan-500/10 text-cyan-300",
  },
  retry: {
    label: "Retry",
    icon: RotateCw,
    className: "border-amber-500/30 bg-amber-500/10 text-amber-300",
  },
  chain: {
    label: "Chain",
    icon: Link2,
    className: "border-orange-500/30 bg-orange-500/10 text-orange-300",
  },
  system: {
    label: "System",
    icon: Cpu,
    className: "border-zinc-500/30 bg-zinc-500/10 text-zinc-300",
  },
};

const outcomeConfig: Record<
  ExecutionOutcome,
  {
    label: string;
    icon: typeof CheckCircle2;
    className: string;
  }
> = {
  completed: {
    label: "Done",
    icon: CheckCircle2,
    className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
  },
  running: {
    label: "Run",
    icon: Clock,
    className: "border-blue-500/30 bg-blue-500/10 text-blue-300",
  },
  error: {
    label: "Error",
    icon: AlertCircle,
    className: "border-rose-500/30 bg-rose-500/10 text-rose-300",
  },
  blocked: {
    label: "Blocked",
    icon: Ban,
    className: "border-amber-500/30 bg-amber-500/10 text-amber-300",
  },
};

function triggerSizeClass(size: "sm" | "md"): string {
  return size === "sm"
    ? "px-2 py-0.5 text-[10px]"
    : "px-2.5 py-1 text-[11px]";
}

function iconSizeClass(size: "sm" | "md"): string {
  return size === "sm" ? "h-3 w-3" : "h-3.5 w-3.5";
}

function outcomeSizeClass(size: "sm" | "md"): string {
  return size === "sm" ? "px-1.5 py-0.5 text-[10px]" : "px-2 py-1 text-[11px]";
}

function outcomeCompactSizeClass(size: "sm" | "md"): string {
  return size === "sm" ? "px-1 py-0.5 text-[9px]" : "px-1.5 py-0.5 text-[10px]";
}

export function TriggerBadge({
  type,
  size = "md",
  className,
}: {
  type: TriggerType;
  size?: "sm" | "md";
  className?: string;
}) {
  const config = triggerConfig[type];
  const Icon = config.icon;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-full border font-semibold tracking-wide",
        triggerSizeClass(size),
        config.className,
        className,
      )}
    >
      <Icon className={iconSizeClass(size)} />
      {config.label}
    </span>
  );
}

export function OutcomeBadge({
  outcome,
  size = "md",
  compact = false,
  className,
}: {
  outcome: ExecutionOutcome;
  size?: "sm" | "md";
  compact?: boolean;
  className?: string;
}) {
  const config = outcomeConfig[outcome];
  const Icon = config.icon;
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border font-semibold tracking-wide",
        compact ? "gap-0.5" : "gap-1",
        compact ? outcomeCompactSizeClass(size) : outcomeSizeClass(size),
        config.className,
        className,
      )}
    >
      <Icon className={iconSizeClass(size)} />
      {config.label}
    </span>
  );
}
