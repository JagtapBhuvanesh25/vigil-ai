"use client";

import { useEffect, useState } from "react";
import { Search, RefreshCw, ExternalLink } from "lucide-react";
import { api } from "@/lib/api";
import type { Email } from "@/lib/api";
import { cn, timeAgo, classificationClass, tierColor } from "@/lib/utils";

export default function IncidentsPage() {
  const [emails, setEmails] = useState<Email[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [filterType, setFilterType] = useState("all");

  async function load() {
    setLoading(true);
    try {
      const res = await api.emails.list();
      setEmails(res.emails ?? []);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  // Filter to non-safe or all
  const incidents = emails.filter((e) => {
    const matchType = filterType === "all" || e.classification === filterType;
    const matchSearch =
      !search ||
      e.sender.toLowerCase().includes(search.toLowerCase()) ||
      e.subject.toLowerCase().includes(search.toLowerCase()) ||
      e.session_id.toLowerCase().includes(search.toLowerCase());
    return matchType && matchSearch;
  });

  const TYPE_OPTIONS = ["all", "malicious", "suspicious", "honeytoken", "safe"];
  const TYPE_ICONS: Record<string, string> = {
    malicious: "🔴",
    suspicious: "⚠️",
    honeytoken: "⚡",
    safe: "✅",
    pending: "⏳",
  };

  return (
    <div className="page-container space-y-5">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold">Incident History</h1>
          <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
            All security events across all time
          </p>
        </div>
        <button
          id="incidents-refresh"
          onClick={load}
          className="p-2 rounded-lg"
          style={{ background: "var(--bg-elevated)", color: "var(--text-secondary)", border: "1px solid var(--border-subtle)" }}
        >
          <RefreshCw className={cn("w-4 h-4", loading && "animate-spin")} />
        </button>
      </div>

      {/* Controls */}
      <div className="flex flex-wrap gap-3 items-center">
        <div
          className="flex items-center gap-2 flex-1 min-w-48 px-3 py-2 rounded-lg"
          style={{ background: "var(--bg-surface)", border: "1px solid var(--border-subtle)" }}
        >
          <Search className="w-4 h-4 shrink-0" style={{ color: "var(--text-muted)" }} />
          <input
            id="incidents-search"
            placeholder="Search email, session, sender…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="bg-transparent flex-1 text-sm outline-none"
            style={{ color: "var(--text-primary)" }}
          />
        </div>
        <div className="flex gap-1 flex-wrap">
          {TYPE_OPTIONS.map((t) => (
            <button
              key={t}
              id={`incident-filter-${t}`}
              onClick={() => setFilterType(t)}
              className="px-3 py-1.5 rounded-md text-xs font-medium capitalize"
              style={{
                background: filterType === t ? "var(--brand-dim)" : "var(--bg-elevated)",
                color: filterType === t ? "var(--brand)" : "var(--text-secondary)",
                border: "1px solid",
                borderColor: filterType === t ? "rgba(5,213,250,0.3)" : "var(--border-subtle)",
              }}
            >
              {t}
            </button>
          ))}
        </div>
      </div>

      {/* Incident table */}
      <div className="vigil-card p-0 overflow-hidden">
        {/* Header */}
        <div
          className="grid grid-cols-12 gap-2 px-5 py-3 border-b text-xs font-semibold uppercase tracking-wider"
          style={{ borderColor: "var(--border-subtle)", color: "var(--text-muted)" }}
        >
          <span className="col-span-2">Time</span>
          <span className="col-span-2">Type</span>
          <span className="col-span-2">Session</span>
          <span className="col-span-4">Summary</span>
          <span className="col-span-1">Risk</span>
          <span className="col-span-1" />
        </div>

        {loading ? (
          <div className="p-8 text-center text-sm" style={{ color: "var(--text-muted)" }}>Loading…</div>
        ) : incidents.length === 0 ? (
          <div className="p-8 text-center text-sm" style={{ color: "var(--text-muted)" }}>No incidents found.</div>
        ) : (
          <div className="divide-y" style={{ borderColor: "var(--border-subtle)" }}>
            {incidents.map((email) => {
              const tier = email.risk_score < 20 ? 0 : email.risk_score < 40 ? 1 : email.risk_score < 60 ? 2 : email.risk_score < 80 ? 3 : 4;
              return (
                <div
                  key={email.id}
                  className="grid grid-cols-12 gap-2 px-5 py-3 text-xs items-center"
                  onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "var(--bg-elevated)"; }}
                  onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = ""; }}
                  id={`incident-row-${email.id}`}
                >
                  <span className="col-span-2" style={{ color: "var(--text-muted)" }}>
                    {timeAgo(email.created_at)}
                  </span>
                  <div className="col-span-2">
                    <span className={cn("tier-badge", classificationClass(email.classification))}>
                      {TYPE_ICONS[email.classification] ?? "●"} {email.classification.toUpperCase()}
                    </span>
                  </div>
                  <span className="col-span-2 font-mono truncate" style={{ color: "var(--text-secondary)" }}>
                    {email.session_id.slice(0, 8)}…
                  </span>
                  <div className="col-span-4 min-w-0">
                    <p className="truncate" style={{ color: "var(--text-primary)" }}>
                      {email.sender}
                    </p>
                    <p className="truncate mt-0.5" style={{ color: "var(--text-muted)" }}>
                      {email.subject || "(no subject)"}
                    </p>
                  </div>
                  <span className="col-span-1 font-bold" style={{ color: tierColor(tier) }}>
                    {Math.round(email.risk_score)}
                  </span>
                  <div className="col-span-1 flex justify-end">
                    <a href={`/inbox/${email.id}`} title="View email detail">
                      <ExternalLink className="w-3.5 h-3.5" style={{ color: "var(--text-muted)" }} />
                    </a>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
