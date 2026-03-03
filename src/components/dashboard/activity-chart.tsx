/**
 * @fileoverview ClawSight SIEM module: platform/src/components/dashboard/activity-chart.tsx.
 */
"use client";

import {
  Line,
  LineChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export type ActivityChartPoint = {
  time: string;
  events: number;
};

type ActivityChartProps = {
  data: ActivityChartPoint[];
};

export function ActivityChart({ data }: ActivityChartProps) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">Total Activity</CardTitle>
        <CardDescription>Telemetry events per hour for the last 24 hours</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="h-60 min-w-0 w-full">
          <ResponsiveContainer
            width="100%"
            height="100%"
            minWidth={280}
            minHeight={240}
            debounce={150}
            initialDimension={{ width: 640, height: 240 }}
          >
            <LineChart data={data}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(228 10% 16%)" />
              <XAxis
                dataKey="time"
                tick={{ fontSize: 10, fill: "hsl(220 8% 55%)" }}
                tickLine={false}
                axisLine={false}
                interval={3}
              />
              <YAxis
                tick={{ fontSize: 10, fill: "hsl(220 8% 55%)" }}
                tickLine={false}
                axisLine={false}
                width={40}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: "hsl(228 12% 10%)",
                  border: "1px solid hsl(228 10% 16%)",
                  borderRadius: "6px",
                  fontSize: "12px",
                  color: "hsl(220 14% 92%)",
                }}
              />
              <Line
                type="monotone"
                dataKey="events"
                stroke="hsl(221 83% 53%)"
                strokeWidth={2}
                dot={false}
                activeDot={{ r: 4 }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}
