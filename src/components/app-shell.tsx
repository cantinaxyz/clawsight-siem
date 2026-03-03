/**
 * @fileoverview ClawSight SIEM module: platform/src/components/app-shell.tsx.
 */
import Link from "next/link";
import {
  Bell,
  CalendarClock,
  Gavel,
  LayoutDashboard,
  Radio,
  Route,
  Settings2,
  Shield,
} from "lucide-react";
import { cn } from "@/lib/utils";

type NavId = "dashboard" | "events" | "alerts" | "traces" | "agents" | "safety" | "policies";

type AppShellProps = {
  children: React.ReactNode;
  title: string;
  subtitle?: string;
  activeNav: NavId;
};

const navItems: Array<{
  id: NavId;
  label: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
}> = [
  { id: "dashboard", label: "Dashboard", href: "/", icon: LayoutDashboard },
  { id: "events", label: "Events", href: "/events", icon: CalendarClock },
  { id: "traces", label: "Executions", href: "/executions", icon: Route },
  { id: "alerts", label: "Alerts", href: "/alerts", icon: Bell },
  { id: "agents", label: "Agents", href: "/agents", icon: Settings2 },
  { id: "safety", label: "Safety", href: "/safety", icon: Gavel },
];

export default function AppShell({ children, title, subtitle, activeNav }: AppShellProps) {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <div className="grid min-h-screen md:grid-cols-[14rem_1fr]">
        <aside className="hidden border-r border-border bg-sidebar md:flex md:flex-col">
          <div className="flex items-center gap-2 px-5 py-5">
            <Shield className="h-5 w-5 text-primary" />
            <span className="text-sm font-semibold tracking-tight text-sidebar-accent-foreground">
              ClawSight SIEM
            </span>
          </div>

          <nav className="flex-1 px-3 py-2" aria-label="Primary navigation">
            <ul className="flex flex-col gap-1">
              {navItems.map((item) => (
                <li key={item.id}>
                  <Link
                    href={item.href}
                    className={cn(
                      "flex items-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                      activeNav === item.id
                        ? "bg-sidebar-accent text-sidebar-accent-foreground"
                        : "text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
                    )}
                  >
                    <item.icon className="h-4 w-4" />
                    {item.label}
                  </Link>
                </li>
              ))}
            </ul>
          </nav>

          <div className="border-t border-sidebar-border px-5 py-4">
            <p className="text-xs text-muted-foreground">OpenClaw telemetry operations</p>
          </div>
        </aside>

        <div className="flex min-w-0 flex-col">
          <header className="sticky top-0 z-20 border-b border-border bg-card/95 px-4 py-3 backdrop-blur md:px-6">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
              <div>
                <h1 className="text-base font-semibold text-foreground">{title}</h1>
                {subtitle ? <p className="text-sm text-muted-foreground">{subtitle}</p> : null}
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <Link
                  href="/api/telemetry/events"
                  className="inline-flex items-center rounded-md border border-border bg-secondary/60 px-2 py-1 text-xs text-muted-foreground hover:text-foreground"
                >
                  Events API
                </Link>
                <Link
                  href="/api/security/alerts"
                  className="inline-flex items-center rounded-md border border-border bg-secondary/60 px-2 py-1 text-xs text-muted-foreground hover:text-foreground"
                >
                  Alerts API
                </Link>
                <span className="inline-flex items-center gap-1 rounded-md bg-primary/10 px-2 py-1 text-xs font-medium text-primary">
                  <Radio className="h-3 w-3 animate-pulse" />
                  SSE Live
                </span>
              </div>
            </div>
            <nav className="mt-3 flex flex-wrap gap-1 md:hidden" aria-label="Mobile navigation">
              {navItems.map((item) => (
                <Link
                  key={item.id}
                  href={item.href}
                  className={cn(
                    "inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs font-medium",
                    activeNav === item.id
                      ? "bg-accent text-accent-foreground"
                      : "text-muted-foreground hover:bg-accent hover:text-accent-foreground",
                  )}
                >
                  <item.icon className="h-3.5 w-3.5" />
                  {item.label}
                </Link>
              ))}
            </nav>
          </header>
          <main className="mx-auto flex w-full max-w-[1700px] flex-1 flex-col gap-6 p-4 md:p-6">{children}</main>
        </div>
      </div>
    </div>
  );
}
