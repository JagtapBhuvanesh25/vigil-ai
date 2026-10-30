"use client";

import { useEffect, useState } from "react";
import { AlertTriangle, CheckCircle, XCircle, RefreshCw, ExternalLink, Clock } from "lucide-react";
import { api } from "@/lib/api";
import type { Escalation } from "@/lib/api";
import { cn, timeAgo } from "@/lib/utils";

function PendingCard({ esc, onResolved }: { esc: Escalation; onResolved: () => void }) {
  const [loading, setLoading] = useState<"approve" | "deny" | null>(null);
  const [done, setDone] = useState<"approved" | "denied" | null>(null);
  const ctx = esc.context as Record<string, string>;

  async function handleApprove() {
    setLoading("approve");
    try {
      await api.escalations.approve(esc.id);
      setDone("approved");
      setTimeout(onResolved, 1000);
    } finally { setLoading(null); }
  }

  async function handleDeny() {
    setLoading("deny");
    try {
      await api.escalations.deny(esc.id);
      setDone("denied");
      setTimeout(onResolved, 1000);
    } finally { setLoading(null); }
  }

  return (
    <div
      className={cn("rounded-xl border-2 p-5 space-y-4", done ? "" : "tier4-pulse")}
      style={{
        background: "var(--bg-surface)",
        borderColor: done
          ? done === "approved" ? "rgba(34,197,94,0.4)" : "rgba(239,68,68,0.4)"
          : "rgba(124,58,237,0.5)",
        boxShadow: done ? undefined : "0 0 30px rgba(124,58,237,0.15)",
      }}
      id={`escalation-card-${esc.id}`}
    >
      <div className="flex items-start gap-3">
        <div
          className="w-10 h-10 rounded-lg flex items-center justify-center shrink-0"
          style={{ background: "rgba(124,58,237,0.15)" }}
        >
          <AlertTriangle className="w-5 h-5" style={{ color: "var(--tier-4)" }} />
        </div>
        <div className="flex-1">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-bold" style={{ color: "var(--tier-4)" }}>
              🚨 TIER 4 — {done ? (done === "approved" ? "APPROVED" : "DENIED") : "PENDING APPROVAL"}
            </h3>
            {!done && (
              <span className="text-xs px-2 py-0.5 rounded-full animate-pulse" style={{ background: "rgba(124,58,237,0.2)", color: "var(--tier-4)" }}>
                LIVE
              </span>
            )}
          </div>
          <p className="text-xs mt-0.5" style={{ color: "var(--text-secondary)" }}>
            Session {esc.session_id.slice(0, 8)} · {timeAgo(esc.triggered_at)}
          </p>
        </div>
      </div>

      {/* Context details */}
      <div className="rounded-lg p-4 space-y-2" style={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)" }}>
        {ctx.trigger && <Row label="Trigger" value={ctx.trigger} />}
        {ctx.last_action && <Row label="Last action" value={ctx.last_action} />}
        {ctx.risk_score !== undefined && <Row label="Risk score" value={`${ctx.risk_score} / 100`} />}
        {ctx.agent_type && <Row label="Agent" value={ctx.agent_type} />}
      </div>

      <a
        href={`/sessions/${esc.session_id}`}
        className="flex items-center gap-1.5 text-xs"
        style={{ color: "var(--brand)" }}
        id={`esc-session-link-${esc.id}`}
      >
        <ExternalLink className="w-3 h-3" /> View Full Session
      </a>

      {/* Result banner */}
      {done && (
        <div
          className="flex items-center gap-2 p-3 rounded-lg text-sm font-semibold fade-in"
          style={{
            background: done === "approved" ? "rgba(34,197,94,0.12)" : "rgba(239,68,68,0.12)",
            color: done === "approved" ? "var(--tier-0)" : "var(--tier-3)",
            border: `1px solid ${done === "approved" ? "rgba(34,197,94,0.3)" : "rgba(239,68,68,0.3)"}`,
          }}
        >
          {done === "approved"
            ? <><CheckCircle className="w-4 h-4" /> Session resumed at Tier 3</>
            : <><XCircle className="w-4 h-4" /> Session terminated</>
          }
        </div>
      )}

      {/* Action buttons */}
      {!done && (
        <div className="flex gap-3">
          <button
            id={`esc-approve-${esc.id}`}
            onClick={handleApprove}
            disabled={!!loading}
            className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-semibold disabled:opacity-60"
            style={{ background: "rgba(34,197,94,0.12)", color: "var(--tier-0)", border: "1px solid rgba(34,197,94,0.3)" }}
          >
            {loading === "approve" ? <span className="animate-spin w-4 h-4 border-2 border-current border-t-transparent rounded-full" /> : <CheckCircle className="w-4 h-4" />}
            Approve — Resume
          </button>
          <button
            id={`esc-deny-${esc.id}`}
            onClick={handleDeny}
            disabled={!!loading}
            className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-semibold disabled:opacity-60"
            style={{ background: "rgba(239,68,68,0.12)", color: "var(--tier-3)", border: "1px solid rgba(239,68,68,0.3)" }}
          >
            {loading === "deny" ? <span className="animate-spin w-4 h-4 border-2 border-current border-t-transparent rounded-full" /> : <XCircle className="w-4 h-4" />}
            Deny — Kill Session
          </button>
        </div>
      )}
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex gap-3">
      <span className="text-xs w-24 shrink-0" style={{ color: "var(--text-muted)" }}>{label}</span>
      <span className="text-xs" style={{ color: "var(--text-primary)" }}>{value}</span>
    </div>
  );
}

export default function EscalationsPage() {
  const [data, setData] = useState<{ pending: Escalation[]; resolved: Escalation[] } | null>(null);
  const [loading, setLoading] = useState(true);

  async function load() {
    setLoading(true);
    try {
      const res = await api.escalations.list();
      setData({ pending: res.pending, resolved: res.resolved });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, []);

  const pending = data?.pending ?? [];
  const resolved = data?.resolved ?? [];

  return (
    <div className="page-container space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold">Escalations</h1>
          <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
            Tier 4 human-in-the-loop approval queue
          </p>
        </div>
        <div className="flex items-center gap-3">
          {pending.length > 0 && (
            <span className="text-sm font-bold px-3 py-1 rounded-full tier4-pulse"
              style={{ background: "rgba(124,58,237,0.2)", color: "var(--tier-4)", border: "1px solid rgba(124,58,237,0.4)" }}>
              {pending.length} PENDING
            </span>
          )}
          <button id="esc-refresh" onClick={load}
            className="p-2 rounded-lg"
            style={{ background: "var(--bg-elevated)", color: "var(--text-secondary)", border: "1px solid var(--border-subtle)" }}>
            <RefreshCw className={cn("w-4 h-4", loading && "animate-spin")} />
          </button>
        </div>
      </div>

      {/* Pending section */}
      <div>
        <h2 className="text-sm font-semibold uppercase tracking-wider mb-3" style={{ color: "var(--text-secondary)" }}>
          Pending Approval ({pending.length})
        </h2>
        {pending.length === 0 ? (
          <div className="vigil-card p-8 text-center">
            <CheckCircle className="w-8 h-8 mx-auto mb-2" style={{ color: "var(--tier-0)" }} />
            <p className="text-sm" style={{ color: "var(--text-muted)" }}>No pending escalations — all clear.</p>
          </div>
        ) : (
          <div className="space-y-4">
            {pending.map((esc) => (
              <PendingCard key={esc.id} esc={esc} onResolved={load} />
            ))}
          </div>
        )}
      </div>

      {/* Resolved section */}
      {resolved.length > 0 && (
        <div>
          <h2 className="text-sm font-semibold uppercase tracking-wider mb-3" style={{ color: "var(--text-secondary)" }}>
            Resolved ({resolved.length})
          </h2>
          <div className="vigil-card p-0 overflow-hidden divide-y" style={{ borderColor: "var(--border-subtle)" }}>
            {resolved.slice(0, 20).map((esc) => (
              <div key={esc.id} className="flex items-center gap-4 px-5 py-3">
                {esc.resolution === "approved"
                  ? <CheckCircle className="w-4 h-4 shrink-0" style={{ color: "var(--tier-0)" }} />
                  : <XCircle className="w-4 h-4 shrink-0" style={{ color: "var(--tier-3)" }} />
                }
                <a href={`/sessions/${esc.session_id}`} className="text-xs font-mono hover:underline" style={{ color: "var(--text-secondary)" }}>
                  {esc.session_id.slice(0, 12)}…
                </a>
                <span
                  className="text-xs px-2 py-0.5 rounded-full capitalize"
                  style={{
                    background: esc.resolution === "approved" ? "rgba(34,197,94,0.12)" : "rgba(239,68,68,0.12)",
                    color: esc.resolution === "approved" ? "var(--tier-0)" : "var(--tier-3)",
                  }}
                >
                  {esc.resolution}
                </span>
                <span className="ml-auto text-xs" style={{ color: "var(--text-muted)" }}>
                  <Clock className="w-3 h-3 inline mr-1" />
                  {esc.resolved_at ? timeAgo(esc.resolved_at) : ""}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
