/**
 * @fileoverview ClawSight SIEM module: platform/src/app/traces/_components/ToolsUsedChips.tsx.
 */
import { Badge } from "@/components/ui/badge";

type ToolsUsedChipsProps = {
  tools: Array<{ name: string; count: number }>;
};

export default function ToolsUsedChips({ tools }: ToolsUsedChipsProps) {
  if (tools.length === 0) {
    return <span className="text-xs text-muted-foreground">No tool calls</span>;
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      {tools.map((tool) => (
        <Badge key={`${tool.name}:${tool.count}`} variant="outline" className="font-normal">
          {tool.name} x{tool.count}
        </Badge>
      ))}
    </div>
  );
}
