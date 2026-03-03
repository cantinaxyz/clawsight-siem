/**
 * @fileoverview ClawSight SIEM module: platform/src/app/agents/[agentKey]/_components/TabNav.tsx.
 */
import Link from "next/link";
import { cn } from "@/lib/utils";

export const AGENT_TABS = [
  { key: "overview", label: "Overview" },
  { key: "timeline", label: "Activity" },
  { key: "tools", label: "Tools" },
  { key: "policy", label: "Policy" },
  { key: "settings", label: "Settings" },
] as const;

export type AgentTabKey = (typeof AGENT_TABS)[number]["key"];

type TabNavProps = {
  activeTab: AgentTabKey;
  baseHref: string;
};

export default function TabNav({ activeTab, baseHref }: TabNavProps) {
  return (
    <div className="border-b border-border bg-background px-4 md:px-6">
      <nav className="flex flex-wrap items-end gap-1">
        {AGENT_TABS.map((tab) => (
          <Link
            key={tab.key}
            href={`${baseHref}?tab=${tab.key}`}
            className={cn(
              "relative rounded-none border-b-2 px-4 py-2.5 text-sm text-muted-foreground transition-colors",
              activeTab === tab.key
                ? "border-primary text-foreground"
                : "border-transparent hover:text-foreground",
            )}
          >
            {tab.label}
          </Link>
        ))}
      </nav>
    </div>
  );
}
