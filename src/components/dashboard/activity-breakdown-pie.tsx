/**
 * @fileoverview ClawSight SIEM module: platform/src/components/dashboard/activity-breakdown-pie.tsx.
 */
"use client";

import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

type ActivityBreakdownPieProps = {
  events: number;
  blocks: number;
  alerts: number;
};

const COLORS = {
  events: "hsl(221 83% 53%)",
  blocks: "hsl(0 72% 51%)",
  alerts: "hsl(38 92% 50%)",
};

export function ActivityBreakdownPie({
  events,
  blocks,
  alerts,
}: ActivityBreakdownPieProps) {
  const data = [
    { name: "Events", value: Math.max(events, 0), color: COLORS.events },
    { name: "Blocks", value: Math.max(blocks, 0), color: COLORS.blocks },
    { name: "Alerts", value: Math.max(alerts, 0), color: COLORS.alerts },
  ];
  const total = data.reduce((sum, row) => sum + row.value, 0);

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">Events / Blocks / Alerts</CardTitle>
        <CardDescription>Total distribution in the last 24 hours</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex items-center gap-4">
          <div className="h-52 w-52 min-h-52 min-w-52 shrink-0">
            <ResponsiveContainer
              width="100%"
              height="100%"
              minWidth={208}
              minHeight={208}
              debounce={150}
              initialDimension={{ width: 208, height: 208 }}
            >
              <PieChart>
                <Pie
                  data={data}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={78}
                  innerRadius={48}
                  stroke="hsl(228 10% 16%)"
                  strokeWidth={1}
                >
                  {data.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: "hsl(228 12% 10%)",
                    border: "1px solid hsl(228 10% 16%)",
                    borderRadius: "6px",
                    fontSize: "12px",
                    color: "hsl(220 14% 92%)",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="min-w-0 flex-1 space-y-2 text-sm">
            {data.map((row) => (
              <div key={row.name} className="flex items-center justify-between gap-3">
                <div className="inline-flex items-center gap-2 text-foreground">
                  <span
                    className="inline-block h-2.5 w-2.5 rounded-full"
                    style={{ backgroundColor: row.color }}
                  />
                  <span>{row.name}</span>
                </div>
                <span className="tabular-nums text-muted-foreground">{row.value}</span>
              </div>
            ))}
            <div className="pt-1 text-xs text-muted-foreground">
              Total: <span className="tabular-nums text-foreground">{total}</span>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
