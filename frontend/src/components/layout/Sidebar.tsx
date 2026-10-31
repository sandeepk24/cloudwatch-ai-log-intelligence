import { Activity, LayoutDashboard, Search, Settings } from "lucide-react";
import { NavLink } from "react-router-dom";
import { useHealth, useLiveness } from "@/api/queries";
import { StatusIndicator } from "@/components/common/StatusIndicator";
import { cn } from "@/lib/utils";

const navItems = [
  { to: "/", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/investigations", icon: Search, label: "Investigations" },
  { to: "/settings", icon: Settings, label: "Settings" },
];

export function Sidebar() {
  const { data: liveness, isLoading: livenessLoading } = useLiveness();
  const { data: health, isLoading } = useHealth();

  return (
    <aside className="flex h-screen w-64 flex-col border-r border-border bg-sidebar">
      <div className="flex items-center gap-3 border-b border-border px-5 py-5">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/15">
          <Activity className="h-5 w-5 text-primary" />
        </div>
        <div>
          <h1 className="text-sm font-semibold text-foreground">CloudWatch AI</h1>
          <p className="text-xs text-muted-foreground">Log Intelligence</p>
        </div>
      </div>

      <nav className="flex-1 space-y-1 px-3 py-4">
        {navItems.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-3 rounded-md px-3 py-2.5 text-sm font-medium transition-colors",
                isActive
                  ? "bg-accent text-sidebar-active"
                  : "text-sidebar-foreground hover:bg-accent/50 hover:text-sidebar-active"
              )
            }
          >
            <Icon className="h-4 w-4" />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="space-y-2 border-t border-border px-5 py-4">
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
          label="AI"
          detail={health?.ai_provider ?? "stub"}
        />
      </div>
    </aside>
  );
}
