/**
 * @fileoverview ClawSight SIEM module: platform/src/app/traces/_components/DetailModeToolbar.tsx.
 */
"use client";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { TraceMode, TraceTab } from "@/lib/traces/types";

type DetailModeToolbarProps = {
  mode: TraceMode;
  tab: TraceTab;
  showInternal: boolean;
  query: string;
  onModeChange: (mode: TraceMode) => void;
  onTabChange: (tab: TraceTab) => void;
  onShowInternalChange: (next: boolean) => void;
  onQueryChange: (value: string) => void;
};

const MODE_OPTIONS: TraceMode[] = ["narrative", "raw"];
const TAB_OPTIONS: TraceTab[] = ["all", "messages", "tools", "policy"];

function labelForMode(mode: TraceMode): string {
  if (mode === "narrative") return "Narrative";
  return "Raw";
}

function labelForTab(tab: TraceTab): string {
  if (tab === "all") return "All";
  if (tab === "messages") return "Messages";
  if (tab === "tools") return "Tools";
  return "Policy";
}

export default function DetailModeToolbar({
  mode,
  tab,
  showInternal,
  query,
  onModeChange,
  onTabChange,
  onShowInternalChange,
  onQueryChange,
}: DetailModeToolbarProps) {
  return (
    <div className="sticky top-[68px] z-10 rounded-lg border border-border bg-card/95 p-3 backdrop-blur">
      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Mode</span>
          {MODE_OPTIONS.map((option) => (
            <Button
              key={option}
              type="button"
              size="sm"
              variant={option === mode ? "default" : "outline"}
              onClick={() => onModeChange(option)}
            >
              {labelForMode(option)}
            </Button>
          ))}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Filter</span>
          {TAB_OPTIONS.map((option) => (
            <Button
              key={option}
              type="button"
              size="sm"
              variant={option === tab ? "secondary" : "outline"}
              onClick={() => onTabChange(option)}
            >
              {labelForTab(option)}
            </Button>
          ))}

          <Button
            type="button"
            size="sm"
            variant={showInternal ? "secondary" : "outline"}
            onClick={() => onShowInternalChange(!showInternal)}
          >
            Internal hooks
          </Button>
        </div>

        <Input
          value={query}
          onChange={(event) => onQueryChange(event.target.value)}
          placeholder="Search within this trace"
          className="h-9"
        />
      </div>
    </div>
  );
}
