"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { ArrowLeft, Shield, AlertTriangle, Link as LinkIcon, Send } from "lucide-react";
import { api } from "@/lib/api";
import type { Email, Verdict } from "@/lib/api";
import { cn, classificationClass, tierLabel, tierColor } from "@/lib/utils";

function RiskGauge({ score }: { score: number }) {
  const tier = score < 20 ? 0 : score < 40 ? 1 : score < 60 ? 2 : score < 80 ? 3 : 4;
  const color = tierColor(tier);
  return (
    <div className="vigil-card text-center">
      <p className="text-xs mb-3 font-semibold uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>Risk Score</p>
      <p className="text-5xl font-bold mb-3" style={{ color }}>{Math.round(score)}</p>
      <div className="w-full h-2 rounded-full mb-2" style={{ background: "var(--bg-elevated)" }}>
        <div className="h-full rounded-full transition-all" style={{ width: `${score}%`, background: color }} />
      </div>
      <span className={cn("tier-badge", `tier-${tier}`)} style={{ justifyContent: "center" }}>
        TIER {tier} — {tierLabel(tier)}
      </span>
    </div>
  );
}

export default function EmailDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [email, setEmail] = useState<(Email & { verdict?: Verdict }) | null>(null);
  const [loading, setLoading] = useState(true);
  const [replyText, setReplyText] = useState("");
  const [sendStatus, setSendStatus] = useState<"idle" | "sending" | "sent">("idle");

  useEffect(() => {
    if (!id) return;
    api.emails.get(id)
      .then(setEmail)
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) {
    return (
      <div className="page-container flex items-center justify-center h-64 text-sm" style={{ color: "var(--text-muted)" }}>
        Loading email…
      </div>
    );
  }

  if (!email) {
    return (
      <div className="page-container text-sm" style={{ color: "var(--text-muted)" }}>
        Email not found. <a href="/inbox" style={{ color: "var(--brand)" }}>← Back to Inbox</a>
      </div>
    );
  }

  const verdict: Verdict | null = email.verdict
    ? email.verdict
    : email.verdict_json
    ? (JSON.parse(email.verdict_json) as Verdict)
    : null;

  const isSafe = email.classification === "safe";
  const isHoneytoken = email.classification === "honeytoken";

  async function handleSendReply() {
    setSendStatus("sending");
    await new Promise((r) => setTimeout(r, 800)); // mock
    setSendStatus("sent");
  }

  return (
    <div className="page-container space-y-5">
      <a
        href="/inbox"
        id="email-back"
        className="flex items-center gap-2 text-sm"
        style={{ color: "var(--brand)" }}
      >
        <ArrowLeft className="w-4 h-4" /> Back to Inbox
      </a>

      {/* Header meta */}
      <div className="vigil-card space-y-1">
        <div className="flex items-start gap-3">
          <div className="flex-1 min-w-0">
            <h1 className="text-xl font-bold truncate" style={{ color: "var(--text-primary)" }}>
              {email.subject || "(no subject)"}
            </h1>
            <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
              From: <span style={{ color: "var(--text-primary)" }}>{email.sender}</span>
            </p>
            <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
              {email.received_at ? new Date(email.received_at).toLocaleString() : "Unknown time"}
            </p>
          </div>
          <span className={cn("tier-badge text-sm", classificationClass(email.classification))}>
            ● {(email.classification || "pending").toUpperCase()}
          </span>
        </div>
        {isHoneytoken && (
          <div
            className="flex items-center gap-2 p-2 rounded-lg mt-2 text-xs font-semibold"
            style={{ background: "rgba(124,58,237,0.15)", color: "var(--tier-4)", border: "1px solid rgba(124,58,237,0.3)" }}
          >
            ⚡ HONEYTOKEN HIT — This email address is a decoy planted by Vigil AI
          </div>
        )}
      </div>

      {/* Verdict + Risk side by side */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Verdict card */}
        <div className="vigil-card space-y-3">
          <div className="flex items-center gap-2">
            {isSafe
              ? <Shield className="w-5 h-5" style={{ color: "var(--tier-0)" }} />
              : <AlertTriangle className="w-5 h-5" style={{ color: "var(--tier-3)" }} />
            }
            <h2 className="text-sm font-semibold uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>
              Verdict
            </h2>
          </div>

          {verdict ? (
            <div>
              <p className="text-lg font-bold" style={{ color: tierColor(email.risk_score < 20 ? 0 : email.risk_score < 40 ? 1 : 2) }}>
                {verdict.verdict?.toUpperCase()}
              </p>
              <p className="text-xs mt-1" style={{ color: "var(--text-muted)" }}>
                Confidence: {Math.round((verdict.confidence ?? 0) * 100)}%
              </p>
              {verdict.reasoning && verdict.reasoning.length > 0 && (
                <ul className="mt-3 space-y-1">
                  {verdict.reasoning.map((r, i) => (
                    <li key={i} className="text-xs flex gap-2" style={{ color: "var(--text-secondary)" }}>
                      <span style={{ color: "var(--brand)" }}>•</span> {r}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ) : (
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>
              No detailed verdict available yet. Use the Analyze button or process via phishing analyzer.
            </p>
          )}
        </div>

        {/* Risk gauge */}
        <RiskGauge score={email.risk_score} />
      </div>

      {/* IOCs */}
      {verdict?.iocs && (
        <div className="vigil-card space-y-3">
          <h2 className="text-sm font-semibold uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>
            Indicators of Compromise
          </h2>
          {verdict.iocs.urls && verdict.iocs.urls.length > 0 && (
            <div>
              <p className="text-xs font-medium mb-2" style={{ color: "var(--text-muted)" }}>URLs found:</p>
              {verdict.iocs.urls.map((url, i) => (
                <div key={i} className="flex items-center gap-2 p-2 rounded mb-1" style={{ background: "var(--bg-elevated)" }}>
                  <LinkIcon className="w-3 h-3 shrink-0" style={{ color: "var(--tier-3)" }} />
                  <span className="text-xs font-mono truncate" style={{ color: "var(--tier-3)" }}>{url}</span>
                  <span className="ml-auto text-xs" style={{ color: "var(--tier-3)" }}>BLOCKED ●</span>
                </div>
              ))}
            </div>
          )}
          {verdict.iocs.headers && verdict.iocs.headers.length > 0 && (
            <div>
              <p className="text-xs font-medium mb-2" style={{ color: "var(--text-muted)" }}>Header anomalies:</p>
              {verdict.iocs.headers.map((h, i) => (
                <p key={i} className="text-xs mb-1" style={{ color: "var(--tier-2)" }}>• {h}</p>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Actions */}
      <div className="vigil-card space-y-3">
        <h2 className="text-sm font-semibold uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>
          Actions
        </h2>
        {isSafe ? (
          <div className="space-y-3">
            <textarea
              id="reply-editor"
              className="w-full h-32 p-3 rounded-lg text-sm resize-none outline-none"
              style={{
                background: "var(--bg-elevated)",
                border: "1px solid var(--border-default)",
                color: "var(--text-primary)",
              }}
              placeholder="Write your reply…"
              value={replyText}
              onChange={(e) => setReplyText(e.target.value)}
            />
            <button
              id="send-reply-btn"
              onClick={handleSendReply}
              disabled={sendStatus !== "idle" || !replyText.trim()}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition-opacity disabled:opacity-50"
              style={{ background: "var(--brand-dim)", color: "var(--brand)", border: "1px solid rgba(5,213,250,0.3)" }}
            >
              {sendStatus === "sending" ? (
                <span className="animate-spin w-4 h-4 border-2 border-current border-t-transparent rounded-full" />
              ) : sendStatus === "sent" ? (
                "✓ Sent"
              ) : (
                <><Send className="w-4 h-4" /> Send Reply</>
              )}
            </button>
          </div>
        ) : (
          <div className="flex flex-wrap gap-2">
            <button
              id="action-quarantine"
              className="px-4 py-2 rounded-lg text-sm font-medium"
              style={{ background: "rgba(239,68,68,0.12)", color: "var(--tier-3)", border: "1px solid rgba(239,68,68,0.25)" }}
            >
              Quarantine Email
            </button>
            <button
              id="action-report"
              className="px-4 py-2 rounded-lg text-sm font-medium"
              style={{ background: "rgba(249,115,22,0.12)", color: "var(--tier-2)", border: "1px solid rgba(249,115,22,0.25)" }}
            >
              Report as Phishing
            </button>
            <button
              id="action-mark-safe"
              className="px-4 py-2 rounded-lg text-sm font-medium"
              style={{ background: "rgba(34,197,94,0.12)", color: "var(--tier-0)", border: "1px solid rgba(34,197,94,0.25)" }}
            >
              Mark as Safe
            </button>
            <p className="w-full text-xs mt-1" style={{ color: "var(--text-muted)" }}>
              Reply and Forward are disabled — classification is {email.classification}.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
