"use client";

import { useEffect, useState } from "react";
import { Bell, Wifi, WifiOff } from "lucide-react";
import { useAlertStore } from "@/lib/store";
import { cn } from "@/lib/utils";

export function Topbar() {
  const [time, setTime] = useState("");
  const [wsConnected, setWsConnected] = useState(false);
  const { unreadCount, markAllRead } = useAlertStore();

  useEffect(() => {
    const tick = () => setTime(new Date().toLocaleTimeString());
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  // Listen for WS connection events via a custom DOM event
  useEffect(() => {
    const handle = (e: Event) => {
      setWsConnected((e as CustomEvent<boolean>).detail);
    };
    window.addEventListener("vigil-ws-status", handle);
    return () => window.removeEventListener("vigil-ws-status", handle);
  }, []);

  return (
    <header
      className="h-14 flex items-center justify-between px-6 border-b shrink-0 sticky top-0 z-30"
      style={{
        background: "rgba(13,17,23,0.9)",
        backdropFilter: "blur(12px)",
        borderColor: "var(--border-subtle)",
      }}
    >
      {/* Status dot */}
      <div className="flex items-center gap-3">
        <span
          className="inline-block w-2 h-2 rounded-full"
          style={{ background: "var(--tier-0)", boxShadow: "0 0 6px var(--tier-0)" }}
        />
        <span className="text-xs font-medium" style={{ color: "var(--text-secondary)" }}>
          Containment Engine Active
        </span>
      </div>

      {/* Right side */}
      <div className="flex items-center gap-4">
        {/* WS indicator */}
        <div
          className="flex items-center gap-1.5 text-xs"
          style={{ color: wsConnected ? "var(--tier-0)" : "var(--text-muted)" }}
          title={wsConnected ? "Live alerts connected" : "Live alerts disconnected"}
        >
          {wsConnected ? <Wifi className="w-3.5 h-3.5" /> : <WifiOff className="w-3.5 h-3.5" />}
          <span className="hidden sm:inline">{wsConnected ? "Live" : "Offline"}</span>
        </div>

        {/* Time */}
        <span
          className="text-xs tabular-nums"
          style={{ color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}
        >
          {time}
        </span>

        {/* Alert bell */}
        <button
          id="topbar-alerts-btn"
          onClick={markAllRead}
          aria-label="Mark all alerts as read"
          className="relative p-1.5 rounded-md transition-colors"
          style={{ color: "var(--text-secondary)" }}
          onMouseEnter={(e) => {
            (e.currentTarget as HTMLElement).style.background = "var(--bg-hover)";
            (e.currentTarget as HTMLElement).style.color = "var(--text-primary)";
          }}
          onMouseLeave={(e) => {
            (e.currentTarget as HTMLElement).style.background = "transparent";
            (e.currentTarget as HTMLElement).style.color = "var(--text-secondary)";
          }}
        >
          <Bell className="w-4 h-4" />
          {unreadCount > 0 && (
            <span
              className={cn(
                "absolute -top-0.5 -right-0.5 w-4 h-4 rounded-full text-white text-xs flex items-center justify-center font-bold",
                "animate-bounce"
              )}
              style={{ background: "var(--tier-4)", fontSize: "0.6rem" }}
            >
              {unreadCount > 9 ? "9+" : unreadCount}
            </span>
          )}
        </button>
      </div>
    </header>
  );
}
