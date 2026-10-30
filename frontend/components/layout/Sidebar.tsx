"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  Mail,
  Activity,
  Globe,
  ScrollText,
  BarChart2,
  AlertTriangle,
  ShieldAlert,
  Settings,
  Shield,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useUIStore, useAlertStore } from "@/lib/store";

const NAV_ITEMS = [
  { href: "/dashboard",    label: "Dashboard",       icon: LayoutDashboard },
  { href: "/inbox",        label: "Inbox",           icon: Mail },
  { href: "/sessions",     label: "Sessions",        icon: Activity },
  { href: "/threat-intel", label: "Threat Intel",    icon: Globe },
  { href: "/audit",        label: "Audit Log",       icon: ScrollText },
  { href: "/analytics",    label: "Analytics",       icon: BarChart2 },
  { href: "/incidents",    label: "Incidents",       icon: AlertTriangle },
  { href: "/escalations",  label: "Escalations",     icon: ShieldAlert },
  { href: "/settings",     label: "Settings",        icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();
  const { sidebarCollapsed, toggleSidebar } = useUIStore();
  const pendingCount = useAlertStore((s) => s.pendingEscalations.length);

  return (
    <aside
      className={cn(
        "flex flex-col shrink-0 h-screen sticky top-0 z-40 transition-all duration-200",
        "border-r",
        sidebarCollapsed ? "w-16" : "w-60"
      )}
      style={{
        background: "var(--bg-surface)",
        borderColor: "var(--border-subtle)",
      }}
    >
      {/* Logo */}
      <div
        className="flex items-center h-14 px-4 border-b shrink-0"
        style={{ borderColor: "var(--border-subtle)" }}
      >
        <div
          className="flex items-center justify-center w-8 h-8 rounded-lg shrink-0"
          style={{ background: "linear-gradient(135deg, #05D5FA 0%, #7C3AED 100%)" }}
        >
          <Shield className="w-4 h-4 text-white" />
        </div>
        {!sidebarCollapsed && (
          <span className="ml-3 text-base font-bold text-white tracking-tight truncate">
            Vigil AI
          </span>
        )}
      </div>

      {/* Nav */}
      <nav className="flex-1 px-2 py-3 space-y-0.5 overflow-y-auto scrollbar-thin">
        {NAV_ITEMS.map(({ href, label, icon: Icon }) => {
          const active = pathname === href || pathname.startsWith(`${href}/`);
          const isEscalations = href === "/escalations";
          return (
            <Link
              key={href}
              href={href}
              id={`nav-${label.toLowerCase().replace(/\s+/g, "-")}`}
              title={sidebarCollapsed ? label : undefined}
              className={cn(
                "flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors relative",
                active
                  ? "text-white"
                  : "hover:text-white",
                sidebarCollapsed && "justify-center"
              )}
              style={{
                background: active ? "var(--brand-dim)" : "transparent",
                color: active ? "var(--brand)" : "var(--text-secondary)",
              }}
              onMouseEnter={(e) => {
                if (!active) {
                  (e.currentTarget as HTMLElement).style.background = "var(--bg-hover)";
                  (e.currentTarget as HTMLElement).style.color = "var(--text-primary)";
                }
              }}
              onMouseLeave={(e) => {
                if (!active) {
                  (e.currentTarget as HTMLElement).style.background = "transparent";
                  (e.currentTarget as HTMLElement).style.color = "var(--text-secondary)";
                }
              }}
            >
              <Icon className="w-4 h-4 shrink-0" />
              {!sidebarCollapsed && <span className="truncate">{label}</span>}
              {/* Escalation badge */}
              {isEscalations && pendingCount > 0 && (
                <span
                  className={cn(
                    "ml-auto flex items-center justify-center rounded-full text-white text-xs font-bold",
                    sidebarCollapsed ? "absolute -top-1 -right-1 w-4 h-4" : "w-5 h-5"
                  )}
                  style={{ background: "var(--tier-4)" }}
                >
                  {pendingCount}
                </span>
              )}
            </Link>
          );
        })}
      </nav>

      {/* Collapse toggle */}
      <div
        className="p-2 border-t shrink-0"
        style={{ borderColor: "var(--border-subtle)" }}
      >
        <button
          onClick={toggleSidebar}
          id="sidebar-collapse-btn"
          aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
          className={cn(
            "w-full flex items-center gap-2 px-3 py-2 rounded-md text-xs transition-colors",
            sidebarCollapsed && "justify-center"
          )}
          style={{ color: "var(--text-muted)" }}
          onMouseEnter={(e) => {
            (e.currentTarget as HTMLElement).style.background = "var(--bg-hover)";
            (e.currentTarget as HTMLElement).style.color = "var(--text-secondary)";
          }}
          onMouseLeave={(e) => {
            (e.currentTarget as HTMLElement).style.background = "transparent";
            (e.currentTarget as HTMLElement).style.color = "var(--text-muted)";
          }}
        >
          {sidebarCollapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          {!sidebarCollapsed && <span>Collapse</span>}
        </button>
      </div>
    </aside>
  );
}
