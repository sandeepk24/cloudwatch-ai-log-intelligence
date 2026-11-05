import {
  Activity,
  BarChart3,
  FileSearch,
  LayoutDashboard,
  MessageSquareText,
  ScrollText,
  Settings,
} from "lucide-react";
import { NavLink } from "react-router-dom";
import { useHealth, useLiveness } from "@/api/queries";
import { StatusIndicator } from "@/components/common/StatusIndicator";
import { cn } from "@/lib/utils";
import { isDemoMode } from "@/demo/preferences";

const navItems = [
  { to: "/overview", icon: LayoutDashboard, label: "Overview" },
  { to: "/logs", icon: ScrollText, label: "Log explorer" },
  { to: "/incidents", icon: FileSearch, label: "Incident center" },
  { to: "/investigation", icon: MessageSquareText, label: "AI investigation" },
  { to: "/trends", icon: BarChart3, label: "Trends" },
  { to: "/settings", icon: Settings, label: "Settings" },
];

export function Sidebar() {
  const { data: liveness, isLoading: livenessLoading } = useLiveness();
  const { data: health, isLoading } = useHealth();

  return (
    <aside className="flex h-screen w-64 shrink-0 flex-col border-r border-border bg-sidebar">
      <div className="flex items-center gap-3 border-b border-border px-5 py-5">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/15">
          <Activity className="h-5 w-5 text-primary" aria-hidden />
        </div>
        <div>
          <h1 className="text-sm font-semibold text-foreground">CloudWatch AI Ops</h1>
          <p className="text-xs text-muted-foreground">Operations console</p>
        </div>
      </div>

      <nav className="flex-1 space-y-0.5 px-3 py-4" aria-label="Main">
        {navItems.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-3 rounded-md px-3 py-2.5 text-sm font-medium transition-colors",
                isActive
                  ? "bg-accent text-sidebar-active"
                  : "text-sidebar-foreground hover:bg-accent/50 hover:text-sidebar-active"
              )
            }
          >
            <Icon className="h-4 w-4 shrink-0" aria-hidden />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="space-y-2 border-t border-border px-5 py-4 text-xs">
        {isDemoMode() && (
          <p className="rounded-md bg-warning/10 px-2 py-1 text-warning">Demo data mode</p>
        )}
        <StatusIndicator
          status={liveness ? "connected" : livenessLoading ? "loading" : "disconnected"}
          label="API"
          detail={liveness?.version}
        />
        <StatusIndicator
          status={isLoading ? "loading" : health?.mock_aws ? "connected" : "disconnected"}
          label="AWS"
          detail={health?.aws_mode ?? "unknown"}
        />
        <StatusIndicator
          status={
            isLoading
              ? "loading"
              : health?.bedrock_configured || health?.strands_configured
                ? "connected"
                : "disconnected"
          }
          label="AI agent"
          detail={health?.ai_provider ?? "bedrock"}
        />
      </div>
    </aside>
  );
}
