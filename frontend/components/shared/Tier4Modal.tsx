"use client";

import { useState } from "react";
import { AlertTriangle, X, CheckCircle, XCircle, ExternalLink } from "lucide-react";
import { cn, timeAgo, tierLabel } from "@/lib/utils";
import { api } from "@/lib/api";
import type { Escalation } from "@/lib/api";
import { useAlertStore } from "@/lib/store";

interface Props {
  escalation: Escalation;
  onClose: () => void;
  onResolved: () => void;
}

export function Tier4Modal({ escalation, onClose, onResolved }: Props) {
  const [loading, setLoading] = useState<"approve" | "deny" | null>(null);
  const [result, setResult] = useState<"approved" | "denied" | null>(null);
  const removeEscalation = useAlertStore((s) => s.removeEscalation);

  const ctx = escalation.context as Record<string, string>;

  async function handleApprove() {
    setLoading("approve");
    try {
      await api.escalations.approve(escalation.id);
      setResult("approved");
      removeEscalation(escalation.id);
      setTimeout(() => { onResolved(); onClose(); }, 1500);
    } catch (err) {
      console.error("approve failed", err);
    } finally {
      setLoading(null);
    }
  }

  async function handleDeny() {
    setLoading("deny");
    try {
      await api.escalations.deny(escalation.id);
      setResult("denied");
      removeEscalation(escalation.id);
      setTimeout(() => { onResolved(); onClose(); }, 1500);
    } catch (err) {
      console.error("deny failed", err);
    } finally {
      setLoading(null);
    }
  }

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-50 flex items-center justify-center p-4"
        style={{ background: "rgba(0,0,0,0.75)", backdropFilter: "blur(4px)" }}
        onClick={onClose}
        id="tier4-modal-backdrop"
      >
        {/* Modal card */}
        <div
          className={cn(
            "relative w-full max-w-lg rounded-xl border-2 p-6 shadow-2xl tier4-pulse",
            "transition-all"
          )}
          style={{
            background: "var(--bg-elevated)",
            borderColor: "rgba(124,58,237,0.6)",
            boxShadow: "0 0 40px rgba(124,58,237,0.25)",
          }}
          onClick={(e) => e.stopPropagation()}
          id="tier4-modal"
          role="alertdialog"
          aria-modal="true"
          aria-labelledby="tier4-modal-title"
        >
          {/* Close */}
          <button
            onClick={onClose}
            id="tier4-modal-close"
            className="absolute top-4 right-4 p-1 rounded-md"
            style={{ color: "var(--text-muted)" }}
            aria-label="Close modal"
          >
            <X className="w-4 h-4" />
          </button>

          {/* Header */}
          <div className="flex items-start gap-3 mb-5">
            <div
              className="flex items-center justify-center w-10 h-10 rounded-lg shrink-0"
              style={{ background: "rgba(124,58,237,0.2)" }}
            >
              <AlertTriangle className="w-5 h-5" style={{ color: "var(--tier-4)" }} />
            </div>
            <div>
              <h2
                id="tier4-modal-title"
                className="text-base font-bold mb-0.5"
                style={{ color: "var(--tier-4)" }}
              >
                🚨 TIER 4 — BLACKOUT ESCALATION
              </h2>
              <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
                {timeAgo(escalation.triggered_at)} · Session {escalation.session_id.slice(0, 8)}
              </p>
            </div>
          </div>

          {/* Context */}
          <div
            className="rounded-lg p-4 mb-5 space-y-2"
            style={{ background: "var(--bg-surface)", border: "1px solid var(--border-subtle)" }}
          >
            {ctx.trigger && (
              <Row label="Trigger" value={ctx.trigger} />
            )}
            {ctx.last_action && (
              <Row label="Last action" value={ctx.last_action} />
            )}
            {ctx.risk_score !== undefined && (
              <Row label="Risk score" value={`${ctx.risk_score} / 100`} />
            )}
            {ctx.agent_type && (
              <Row label="Agent" value={ctx.agent_type} />
            )}
          </div>

          {/* Session link */}
          <a
            href={`/sessions/${escalation.session_id}`}
            className="flex items-center gap-1.5 text-xs mb-5"
            style={{ color: "var(--brand)" }}
            id="tier4-modal-session-link"
          >
            <ExternalLink className="w-3 h-3" />
            View full session details
          </a>

          {/* Result banner */}
          {result && (
            <div
              className={cn(
                "flex items-center gap-2 p-3 rounded-lg mb-4 text-sm font-semibold fade-in"
              )}
              style={{
                background: result === "approved" ? "rgba(34,197,94,0.15)" : "rgba(239,68,68,0.15)",
                color: result === "approved" ? "var(--tier-0)" : "var(--tier-3)",
              }}
            >
              {result === "approved"
                ? <><CheckCircle className="w-4 h-4" /> Session resumed at {tierLabel(3)}</>
                : <><XCircle className="w-4 h-4" /> Session terminated</>
              }
            </div>
          )}

          {/* Actions */}
          {!result && (
            <div className="flex gap-3">
              <button
                id="tier4-modal-approve"
                onClick={handleApprove}
                disabled={!!loading}
                className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-semibold transition-opacity"
                style={{
                  background: "rgba(34,197,94,0.15)",
                  color: "var(--tier-0)",
                  border: "1px solid rgba(34,197,94,0.3)",
                  opacity: loading ? 0.6 : 1,
                }}
              >
                {loading === "approve" ? (
                  <span className="animate-spin w-4 h-4 border-2 border-current border-t-transparent rounded-full" />
                ) : (
                  <CheckCircle className="w-4 h-4" />
                )}
                Approve — Resume
              </button>
              <button
                id="tier4-modal-deny"
                onClick={handleDeny}
                disabled={!!loading}
                className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-semibold transition-opacity"
                style={{
                  background: "rgba(239,68,68,0.15)",
                  color: "var(--tier-3)",
                  border: "1px solid rgba(239,68,68,0.3)",
                  opacity: loading ? 0.6 : 1,
                }}
              >
                {loading === "deny" ? (
                  <span className="animate-spin w-4 h-4 border-2 border-current border-t-transparent rounded-full" />
                ) : (
                  <XCircle className="w-4 h-4" />
                )}
                Deny — Kill
              </button>
            </div>
          )}
        </div>
      </div>
    </>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-start gap-3">
      <span className="text-xs w-24 shrink-0" style={{ color: "var(--text-muted)" }}>
        {label}
      </span>
      <span className="text-xs" style={{ color: "var(--text-primary)" }}>
        {value}
      </span>
    </div>
  );
}
