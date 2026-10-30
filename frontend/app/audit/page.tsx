"use client";

import { useEffect, useState } from "react";
import { CheckCircle, XCircle, RefreshCw, Shield, ChevronDown, ChevronRight } from "lucide-react";
import { api } from "@/lib/api";
import type { AuditEntry, AuditListResponse } from "@/lib/api";
import { cn, truncateHash, timeAgo } from "@/lib/utils";

const EVENT_COLORS: Record<string, string> = {
  risk_update: "var(--brand)",
  tier_decision: "var(--tier-2)",
  url_precheck: "var(--tier-1)",
  email_classified: "var(--tier-0)",
  escalation_event: "var(--tier-4)",
  tool_denied: "var(--tier-3)",
};

function EventTypeBadge({ type }: { type: string }) {
  const color = EVENT_COLORS[type] ?? "var(--text-secondary)";
  return (
    <span
      className="text-xs px-2 py-0.5 rounded font-mono"
      style={{ background: `${color}15`, color, border: `1px solid ${color}25` }}
    >
      {type}
    </span>
  );
}

function HashDisplay({ hash, full }: { hash: string; full?: boolean }) {
  const [copied, setCopied] = useState(false);

  function copyHash() {
    navigator.clipboard.writeText(hash).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }

  return (
    <button
      onClick={copyHash}
      title={hash}
      className="hash-display text-left"
      style={{ fontFamily: "var(--font-mono)" }}
    >
      {full ? hash : truncateHash(hash)}
      {copied && <span className="ml-1 text-xs" style={{ color: "var(--tier-0)" }}>✓</span>}
    </button>
  );
}

export default function AuditPage() {
  const [data, setData] = useState<AuditListResponse | null>(null);
  const [page, setPage] = useState(1);
  const [sessionFilter, setSessionFilter] = useState("");
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<{ valid: boolean; detail: string } | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);

  const PAGE_SIZE = 50;

  async function load() {
    setLoading(true);
    try {
      const res = await api.audit.list({
        session_id: sessionFilter || undefined,
        page,
        page_size: PAGE_SIZE,
      });
      setData(res);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, [page, sessionFilter]);

  async function verify() {
    setVerifying(true);
    setVerifyResult(null);
    try {
      const res = await api.audit.verify(sessionFilter || undefined);
      setVerifyResult({
        valid: res.valid,
        detail: res.valid
          ? `✓ VALID — ${res.total_verified} entries verified`
          : `✗ TAMPERED — first broken entry: #${res.tampered_at_seq} in session ${res.tampered_session}`,
      });
    } finally {
      setVerifying(false);
    }
  }

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 1;

  return (
    <div className="page-container space-y-5">
      <div>
        <h1 className="text-3xl font-bold">Audit Log</h1>
        <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
          Cryptographic hash-chain — tamper-evident decision log
        </p>
      </div>

      {/* Controls */}
      <div className="flex flex-wrap items-center gap-3">
        <input
          id="audit-session-filter"
          value={sessionFilter}
          onChange={(e) => { setSessionFilter(e.target.value); setPage(1); }}
          placeholder="Filter by session ID (or leave blank for all)…"
          className="flex-1 min-w-48 px-3 py-2 rounded-lg text-sm outline-none"
          style={{ background: "var(--bg-surface)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)" }}
        />
        <button
          id="audit-refresh"
          onClick={load}
          className="p-2 rounded-lg"
          style={{ background: "var(--bg-elevated)", color: "var(--text-secondary)", border: "1px solid var(--border-subtle)" }}
        >
          <RefreshCw className={cn("w-4 h-4", loading && "animate-spin")} />
        </button>
        <button
          id="audit-verify-btn"
          onClick={verify}
          disabled={verifying}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold disabled:opacity-60"
          style={{ background: "var(--brand-dim)", color: "var(--brand)", border: "1px solid rgba(5,213,250,0.3)" }}
        >
          {verifying ? (
            <span className="animate-spin w-4 h-4 border-2 border-current border-t-transparent rounded-full" />
          ) : (
            <Shield className="w-4 h-4" />
          )}
          Verify Chain
        </button>
      </div>

      {/* Chain status / verify result */}
      {verifyResult && (
        <div
          className={cn(
            "flex items-center gap-3 p-4 rounded-lg border text-sm font-semibold fade-in"
          )}
          style={{
            background: verifyResult.valid ? "rgba(34,197,94,0.1)" : "rgba(239,68,68,0.1)",
            borderColor: verifyResult.valid ? "rgba(34,197,94,0.3)" : "rgba(239,68,68,0.3)",
            color: verifyResult.valid ? "var(--tier-0)" : "var(--tier-3)",
          }}
          id="audit-verify-result"
        >
          {verifyResult.valid
            ? <CheckCircle className="w-5 h-5 shrink-0" />
            : <XCircle className="w-5 h-5 shrink-0" />
          }
          {verifyResult.detail}
        </div>
      )}

      {/* Chain stats */}
      {data && (
        <div className="flex items-center gap-6 text-xs" style={{ color: "var(--text-secondary)" }}>
          <span>Total entries: <strong style={{ color: "var(--text-primary)" }}>{data.total}</strong></span>
          <span>Page: <strong style={{ color: "var(--text-primary)" }}>{page} / {totalPages}</strong></span>
        </div>
      )}

      {/* Audit table */}
      <div className="vigil-card p-0 overflow-hidden">
        {/* Header */}
        <div
          className="grid grid-cols-12 gap-2 px-5 py-3 border-b text-xs font-semibold uppercase tracking-wider"
          style={{ borderColor: "var(--border-subtle)", color: "var(--text-muted)" }}
        >
          <span className="col-span-1">#</span>
          <span className="col-span-3">Event Type</span>
          <span className="col-span-2">Session</span>
          <span className="col-span-3">Payload</span>
          <span className="col-span-2">Hash</span>
          <span className="col-span-1">Time</span>
        </div>

        {loading ? (
          <div className="p-8 text-center text-sm" style={{ color: "var(--text-muted)" }}>Loading…</div>
        ) : !data || data.entries.length === 0 ? (
          <div className="p-8 text-center text-sm" style={{ color: "var(--text-muted)" }}>No audit entries found.</div>
        ) : (
          <div className="divide-y" style={{ borderColor: "var(--border-subtle)" }}>
            {data.entries.map((entry) => {
              let payloadSummary = "";
              try {
                const p = JSON.parse(entry.payload_json);
                payloadSummary = p.tool ?? p.event_type ?? p.type ?? JSON.stringify(p).slice(0, 40);
              } catch {
                payloadSummary = entry.payload_json.slice(0, 40);
              }

              return (
                <div key={entry.id}>
                  <div
                    className="grid grid-cols-12 gap-2 px-5 py-3 text-xs cursor-pointer"
                    onClick={() => setExpanded(expanded === entry.id ? null : entry.id)}
                    onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "var(--bg-elevated)"; }}
                    onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = ""; }}
                  >
                    <span className="col-span-1 font-mono" style={{ color: "var(--text-muted)" }}>
                      {entry.seq_no}
                    </span>
                    <span className="col-span-3">
                      <EventTypeBadge type={entry.event_type} />
                    </span>
                    <span className="col-span-2 font-mono truncate" style={{ color: "var(--text-secondary)" }}>
                      {entry.session_id.slice(0, 8)}…
                    </span>
                    <span className="col-span-3 truncate" style={{ color: "var(--text-secondary)" }}>
                      {payloadSummary}
                    </span>
                    <span className="col-span-2">
                      <HashDisplay hash={entry.entry_hash} />
                    </span>
                    <div className="col-span-1 flex items-center justify-between">
                      <span style={{ color: "var(--text-muted)" }}>
                        {timeAgo(entry.created_at)}
                      </span>
                      {expanded === entry.id
                        ? <ChevronDown className="w-3 h-3" style={{ color: "var(--text-muted)" }} />
                        : <ChevronRight className="w-3 h-3" style={{ color: "var(--text-muted)" }} />
                      }
                    </div>
                  </div>

                  {/* Expanded row */}
                  {expanded === entry.id && (
                    <div
                      className="px-5 py-3 fade-in space-y-2"
                      style={{ background: "var(--bg-elevated)" }}
                    >
                      <div className="flex gap-8 text-xs">
                        <div>
                          <p className="mb-1" style={{ color: "var(--text-muted)" }}>prev_hash</p>
                          <HashDisplay hash={entry.prev_hash} full />
                        </div>
                        <div>
                          <p className="mb-1" style={{ color: "var(--text-muted)" }}>entry_hash</p>
                          <HashDisplay hash={entry.entry_hash} full />
                        </div>
                      </div>
                      <div>
                        <p className="text-xs mb-1" style={{ color: "var(--text-muted)" }}>payload</p>
                        <pre
                          className="text-xs p-3 rounded overflow-auto max-h-40"
                          style={{ background: "var(--bg-base)", color: "var(--brand)", fontFamily: "var(--font-mono)" }}
                        >
                          {JSON.stringify(JSON.parse(entry.payload_json), null, 2)}
                        </pre>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-3">
          <button
            id="audit-prev-page"
            disabled={page === 1}
            onClick={() => setPage((p) => p - 1)}
            className="px-3 py-1.5 rounded-lg text-sm disabled:opacity-40"
            style={{ background: "var(--bg-elevated)", color: "var(--text-secondary)", border: "1px solid var(--border-subtle)" }}
          >
            ← Previous
          </button>
          <span className="text-sm" style={{ color: "var(--text-secondary)" }}>
            Page {page} of {totalPages}
          </span>
          <button
            id="audit-next-page"
            disabled={page === totalPages}
            onClick={() => setPage((p) => p + 1)}
            className="px-3 py-1.5 rounded-lg text-sm disabled:opacity-40"
            style={{ background: "var(--bg-elevated)", color: "var(--text-secondary)", border: "1px solid var(--border-subtle)" }}
          >
            Next →
          </button>
        </div>
      )}
    </div>
  );
}
