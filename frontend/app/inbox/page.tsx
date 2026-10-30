"use client";

import { useEffect, useState } from "react";
import { Search, RefreshCw, ChevronRight } from "lucide-react";
import { api } from "@/lib/api";
import type { Email } from "@/lib/api";
import { cn, timeAgo, classificationClass } from "@/lib/utils";

const FILTERS = ["all", "safe", "suspicious", "malicious", "honeytoken"] as const;
type Filter = (typeof FILTERS)[number];

function RiskBar({ score }: { score: number }) {
  const color =
    score < 20 ? "var(--tier-0)" :
    score < 40 ? "var(--tier-1)" :
    score < 60 ? "var(--tier-2)" :
    score < 80 ? "var(--tier-3)" : "var(--tier-4)";
  return (
    <div className="flex items-center gap-2">
      <div className="w-20 h-1.5 rounded-full" style={{ background: "var(--bg-elevated)" }}>
        <div
          className="h-full rounded-full transition-all"
          style={{ width: `${score}%`, background: color }}
        />
      </div>
      <span className="text-xs tabular-nums w-6" style={{ color: "var(--text-muted)" }}>
        {Math.round(score)}
      </span>
    </div>
  );
}

export default function InboxPage() {
  const [emails, setEmails] = useState<Email[]>([]);
  const [filter, setFilter] = useState<Filter>("all");
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);

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

  const filtered = emails.filter((e) => {
    const matchFilter = filter === "all" || e.classification === filter;
    const matchSearch =
      !search ||
      e.sender.toLowerCase().includes(search.toLowerCase()) ||
      e.subject.toLowerCase().includes(search.toLowerCase());
    return matchFilter && matchSearch;
  });

  return (
    <div className="page-container space-y-5">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold">Inbox</h1>
          <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
            {emails.length} emails processed
          </p>
        </div>
        <button
          id="inbox-refresh"
          onClick={load}
          className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors"
          style={{ background: "var(--bg-elevated)", color: "var(--text-secondary)", border: "1px solid var(--border-subtle)" }}
        >
          <RefreshCw className={cn("w-4 h-4", loading && "animate-spin")} />
          Refresh
        </button>
      </div>

      {/* Controls */}
      <div className="flex flex-wrap items-center gap-3">
        <div
          className="flex items-center gap-2 flex-1 min-w-48 px-3 py-2 rounded-lg"
          style={{ background: "var(--bg-surface)", border: "1px solid var(--border-subtle)" }}
        >
          <Search className="w-4 h-4 shrink-0" style={{ color: "var(--text-muted)" }} />
          <input
            id="inbox-search"
            placeholder="Search sender or subject…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="bg-transparent flex-1 text-sm outline-none"
            style={{ color: "var(--text-primary)" }}
          />
        </div>
        <div className="flex gap-1">
          {FILTERS.map((f) => (
            <button
              key={f}
              id={`inbox-filter-${f}`}
              onClick={() => setFilter(f)}
              className="px-3 py-1.5 rounded-md text-xs font-medium capitalize transition-colors"
              style={{
                background: filter === f ? "var(--brand-dim)" : "var(--bg-elevated)",
                color: filter === f ? "var(--brand)" : "var(--text-secondary)",
                border: "1px solid",
                borderColor: filter === f ? "rgba(5,213,250,0.3)" : "var(--border-subtle)",
              }}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {/* Email list */}
      <div className="vigil-card p-0 overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-sm" style={{ color: "var(--text-muted)" }}>
            Loading emails…
          </div>
        ) : filtered.length === 0 ? (
          <div className="p-8 text-center text-sm" style={{ color: "var(--text-muted)" }}>
            No emails match the current filter.
          </div>
        ) : (
          <div className="divide-y" style={{ borderColor: "var(--border-subtle)" }}>
            {filtered.map((email) => (
              <a
                key={email.id}
                href={`/inbox/${email.id}`}
                id={`email-row-${email.id}`}
                className={cn(
                  "flex items-center gap-4 px-5 py-4 transition-colors group",
                  email.classification === "honeytoken" && "border-l-2"
                )}
                style={{
                  borderLeftColor: email.classification === "honeytoken" ? "var(--tier-4)" : undefined,
                }}
                onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "var(--bg-elevated)"; }}
                onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = ""; }}
              >
                {/* Classification badge */}
                <span
                  className={cn("tier-badge shrink-0 text-xs", classificationClass(email.classification))}
                  style={{ minWidth: 90, justifyContent: "center" }}
                >
                  ● {(email.classification || "pending").toUpperCase()}
                </span>

                {/* Sender + subject */}
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate" style={{ color: "var(--text-primary)" }}>
                    {email.sender || "unknown"}
                  </p>
                  <p className="text-xs truncate mt-0.5" style={{ color: "var(--text-secondary)" }}>
                    {email.subject || "(no subject)"}
                  </p>
                </div>

                {/* Risk bar */}
                <div className="hidden sm:block shrink-0">
                  <RiskBar score={email.risk_score} />
                </div>

                {/* Timestamp */}
                <span className="text-xs shrink-0 w-16 text-right" style={{ color: "var(--text-muted)" }}>
                  {timeAgo(email.created_at)}
                </span>

                <ChevronRight className="w-4 h-4 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity" style={{ color: "var(--text-muted)" }} />
              </a>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
