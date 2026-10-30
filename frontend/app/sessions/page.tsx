"use client";

import { useEffect, useState } from "react";
import { RefreshCw, Plus } from "lucide-react";
import { api } from "@/lib/api";
import type { Session } from "@/lib/api";
import { cn, timeAgo, tierLabel, tierColor } from "@/lib/utils";

function TierDot({ tier }: { tier: number }) {
  return (
    <span
      className="inline-block w-2 h-2 rounded-full shrink-0"
      style={{ background: tierColor(tier), boxShadow: tier >= 3 ? `0 0 6px ${tierColor(tier)}` : undefined }}
    />
  );
}

export default function SessionsPage() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);

  async function load() {
    setLoading(true);
    try {
      const res = await api.sessions.list();
      setSessions(res.sessions ?? []);
    } finally {
      setLoading(false);
    }
  }

  async function createSession() {
    setCreating(true);
    try {
      await api.sessions.create("email");
      await load();
    } finally {
      setCreating(false);
    }
  }

  useEffect(() => { load(); }, []);

  const active = sessions.filter((s) => s.status === "active");
  const completed = sessions.filter((s) => s.status !== "active");

  return (
    <div className="page-container space-y-5">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold">Sessions</h1>
          <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
            {active.length} active · {completed.length} completed
          </p>
        </div>
        <div className="flex gap-2">
          <button
            id="sessions-refresh"
            onClick={load}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm"
            style={{ background: "var(--bg-elevated)", color: "var(--text-secondary)", border: "1px solid var(--border-subtle)" }}
          >
            <RefreshCw className={cn("w-4 h-4", loading && "animate-spin")} />
          </button>
          <button
            id="sessions-new"
            onClick={createSession}
            disabled={creating}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-semibold disabled:opacity-60"
            style={{ background: "var(--brand-dim)", color: "var(--brand)", border: "1px solid rgba(5,213,250,0.3)" }}
          >
            {creating ? (
              <span className="animate-spin w-4 h-4 border-2 border-current border-t-transparent rounded-full" />
            ) : (
              <Plus className="w-4 h-4" />
            )}
            New Session
          </button>
        </div>
      </div>

      {loading ? (
        <div className="p-12 text-center text-sm" style={{ color: "var(--text-muted)" }}>
          Loading sessions…
        </div>
      ) : sessions.length === 0 ? (
        <div className="vigil-card p-12 text-center">
          <p className="text-sm" style={{ color: "var(--text-muted)" }}>
            No sessions yet. Create one to start monitoring.
          </p>
        </div>
      ) : (
        <div className="vigil-card p-0 overflow-hidden divide-y" style={{ borderColor: "var(--border-subtle)" }}>
          {sessions.map((s) => (
            <a
              key={s.id}
              href={`/sessions/${s.id}`}
              id={`session-row-${s.id}`}
              className="flex items-center gap-4 px-5 py-4 transition-colors"
              onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "var(--bg-elevated)"; }}
              onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = ""; }}
            >
              <TierDot tier={s.current_tier} />
              <div className="flex-1 min-w-0">
                <p className="text-sm font-mono truncate" style={{ color: "var(--text-primary)" }}>
                  {s.id.slice(0, 16)}…
                </p>
                <p className="text-xs mt-0.5 capitalize" style={{ color: "var(--text-muted)" }}>
                  {s.agent_type} · {timeAgo(s.created_at)}
                </p>
              </div>
              <div className="text-right shrink-0">
                <p className="text-sm font-bold" style={{ color: tierColor(s.current_tier) }}>
                  {Math.round(s.current_risk)}/100
                </p>
                <span className={cn("tier-badge text-xs", `tier-${s.current_tier}`)}>
                  T{s.current_tier} {tierLabel(s.current_tier)}
                </span>
              </div>
              <span
                className="text-xs px-2 py-0.5 rounded-full capitalize"
                style={{
                  background: s.status === "active" ? "rgba(34,197,94,0.12)" : "var(--bg-elevated)",
                  color: s.status === "active" ? "var(--tier-0)" : "var(--text-muted)",
                }}
              >
                {s.status}
              </span>
            </a>
          ))}
        </div>
      )}
    </div>
  );
}
