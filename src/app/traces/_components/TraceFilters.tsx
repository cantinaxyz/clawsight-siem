/**
 * @fileoverview ClawSight SIEM module: platform/src/app/traces/_components/TraceFilters.tsx.
 */
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

type TraceFiltersProps = {
  searchValue: string;
  sourceType: string;
  agentKey: string;
  agentOptions: Array<{ agentKey: string; label: string }>;
  status: string;
  limit: number;
};

export default function TraceFilters({
  searchValue,
  sourceType,
  agentKey,
  agentOptions,
  status,
  limit,
}: TraceFiltersProps) {
  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base">Filter traces</CardTitle>
        <CardDescription>
          Scope execution traces by source, status, and search terms. System lifecycle traces are shown only when source is set to <code>system</code>.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form method="get" className="grid grid-cols-1 gap-3 md:grid-cols-6 xl:grid-cols-9">
          <div className="xl:col-span-3">
            <Input
              name="q"
              defaultValue={searchValue}
              placeholder="Search trace/session/run/request"
            />
          </div>
          <div>
            <select
              name="agentKey"
              defaultValue={agentKey}
              className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground"
            >
              <option value="">All agents</option>
              {agentOptions.map((agent) => (
                <option key={agent.agentKey} value={agent.agentKey}>
                  {agent.label}
                </option>
              ))}
            </select>
          </div>
          <div>
            <select
              name="sourceType"
              defaultValue={sourceType}
              className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground"
            >
              <option value="">All execution sources</option>
              <option value="user">user</option>
              <option value="cron">cron</option>
              <option value="heartbeat">heartbeat</option>
              <option value="hook">hook</option>
              <option value="webhook">webhook</option>
              <option value="queue">queue</option>
              <option value="system">system</option>
            </select>
          </div>
          <div>
            <select
              name="status"
              defaultValue={status}
              className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground"
            >
              <option value="">All statuses</option>
              <option value="running">running</option>
              <option value="completed">completed</option>
              <option value="failed">failed</option>
            </select>
          </div>
          <Input name="limit" defaultValue={String(limit)} placeholder="Limit" />
          <div className="flex items-center gap-2 md:col-span-2 xl:col-span-2">
            <Button type="submit" size="sm">
              Apply
            </Button>
            <Button variant="outline" size="sm" asChild>
              <Link href="/traces">Reset</Link>
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
