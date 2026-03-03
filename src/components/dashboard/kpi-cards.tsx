/**
 * @fileoverview ClawSight SIEM module: platform/src/components/dashboard/kpi-cards.tsx.
 */
import { AlertTriangle, Bell, ShieldOff, Waves, Wrench } from "lucide-react";

type KpiCardsProps = {
  openAlerts: number;
  highSeverityAlerts: number;
  toolCalls24h: number;
  policyBlocks24h: number;
  events24h: number;
};

const iconClasses = "h-3.5 w-3.5";

export function KpiCards({
  openAlerts,
  highSeverityAlerts,
  toolCalls24h,
  policyBlocks24h,
  events24h,
}: KpiCardsProps) {
  const cards = [
    {
      label: "Open Alerts",
      value: openAlerts.toLocaleString(),
      icon: <Bell className={`${iconClasses} text-severity-critical`} />,
      iconBg: "bg-severity-critical/10",
    },
    {
      label: "High Severity",
      value: highSeverityAlerts.toLocaleString(),
      icon: <AlertTriangle className={`${iconClasses} text-severity-high`} />,
      iconBg: "bg-severity-high/10",
    },
    {
      label: "Tool Calls (24h)",
      value: toolCalls24h.toLocaleString(),
      icon: <Wrench className={`${iconClasses} text-primary`} />,
      iconBg: "bg-primary/10",
    },
    {
      label: "Policy Blocks",
      value: policyBlocks24h.toLocaleString(),
      icon: <ShieldOff className={`${iconClasses} text-severity-high`} />,
      iconBg: "bg-severity-high/10",
    },
    {
      label: "Events (24h)",
      value: events24h.toLocaleString(),
      icon: <Waves className={`${iconClasses} text-chart-2`} />,
      iconBg: "bg-chart-2/10",
    },
  ];

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-5">
      {cards.map((card) => (
        <div key={card.label} className="rounded-lg border border-border bg-card p-4">
          <div className="flex items-center justify-between">
            <p className="text-xs font-medium text-muted-foreground">{card.label}</p>
            <div className={`rounded-md p-1.5 ${card.iconBg}`}>{card.icon}</div>
          </div>
          <p className="mt-2 text-2xl font-semibold tabular-nums text-foreground">
            {card.value}
          </p>
        </div>
      ))}
    </div>
  );
}
