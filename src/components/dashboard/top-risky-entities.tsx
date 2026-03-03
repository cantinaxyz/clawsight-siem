/**
 * @fileoverview ClawSight SIEM module: platform/src/components/dashboard/top-risky-entities.tsx.
 */
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export type TopRiskyEntity = {
  id: string;
  type: "agent" | "request" | "project";
  label: string;
  risk: number;
  relatedAlerts: number;
  relatedEvents: number;
};

type TopRiskyEntitiesProps = {
  entities: TopRiskyEntity[];
};

export function TopRiskyEntities({ entities }: TopRiskyEntitiesProps) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">Top Active Entities</CardTitle>
        <CardDescription>Most active agents, requests, and projects in the last 24 hours</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {entities.length === 0 ? (
          <p className="text-sm text-muted-foreground">No entity activity found in the selected window.</p>
        ) : (
          entities.map((entity) => (
            <div
              key={entity.id}
              className="flex items-center gap-3 rounded-md border border-border bg-secondary/50 p-3"
            >
              <div className="min-w-0">
                <Badge variant="secondary" className="mb-1 capitalize">
                  {entity.type}
                </Badge>
                <p className="truncate text-sm font-medium text-foreground">{entity.label}</p>
              </div>
              <div className="ml-auto flex items-center gap-3">
                <div className="text-right text-xs text-muted-foreground">
                  <div>{entity.relatedAlerts} alerts</div>
                  <div>{entity.relatedEvents} events</div>
                </div>
              </div>
            </div>
          ))
        )}
      </CardContent>
    </Card>
  );
}
