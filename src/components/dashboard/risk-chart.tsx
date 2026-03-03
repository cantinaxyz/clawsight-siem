/**
 * @fileoverview ClawSight SIEM module: platform/src/components/dashboard/risk-chart.tsx.
 */
"use client";

import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export type RiskChartPoint = {
  time: string;
  risk: number;
};

type RiskChartProps = {
  data: RiskChartPoint[];
};

export function RiskChart({ data }: RiskChartProps) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">Risk Score Over Time</CardTitle>
        <CardDescription>Average telemetry risk per hour across the last 24 hours</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="h-60">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data}>
              <defs>
                <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="hsl(168 70% 48%)" stopOpacity={0.28} />
                  <stop offset="95%" stopColor="hsl(168 70% 48%)" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(228 10% 16%)" />
              <XAxis
                dataKey="time"
                tick={{ fontSize: 10, fill: "hsl(220 8% 55%)" }}
                tickLine={false}
                axisLine={false}
                interval={3}
              />
              <YAxis
                domain={[0, 100]}
                tick={{ fontSize: 10, fill: "hsl(220 8% 55%)" }}
                tickLine={false}
                axisLine={false}
                width={32}
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
              <Area
                type="monotone"
                dataKey="risk"
                stroke="hsl(168 70% 48%)"
                fill="url(#riskGradient)"
                strokeWidth={2}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}
