"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, ReferenceLine,
} from "recharts";
import { api } from "@/lib/api";
import type { Session, SessionEvent } from "@/lib/api";
import { cn, tierLabel, tierColor, timeAgo } from "@/lib/utils";

export default function SessionDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);

  async function load() {
    if (!id) return;
    try {
      const s = await api.sessions.get(id);
      setSession(s);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    const interval = setInterval(load, 3000);
    return () => clearInterval(interval);
  }, [id]);

  if (loading) {
    return (
      <div className="page-container flex items-center justify-center h-64 text-sm" style={{ color: "var(--text-muted)" }}>
        Loading session…
      </div>
    );
  }

  if (!session) {
    return (
      <div className="page-container text-sm" style={{ color: "var(--text-muted)" }}>
        Session not found. <a href="/sessions" style={{ color: "var(--brand)" }}>← Back to Sessions</a>
      </div>
    );
  }

  const events: SessionEvent[] = session.events ?? [];
  const tier = session.current_tier;

  // Build chart data from events
  const chartData = events.map((ev, i) => ({
    t: `#${ev.seq_no ?? i}`,
    risk: Math.round(ev.risk_after ?? 0),
    tier: ev.tier_after ?? 0,
  }));
  // Add current point
  chartData.push({ t: "now", risk: Math.round(session.current_risk), tier });

  // Tier timeline: compute time spent per tier
  const tierSpans: { tier: number; count: number }[] = [];
  let prev = 0;
  for (const ev of events) {
    const t = ev.tier_after ?? 0;
    if (tierSpans.length === 0 || tierSpans[tierSpans.length - 1].tier !== t) {
      tierSpans.push({ tier: t, count: 1 });
    } else {
      tierSpans[tierSpans.length - 1].count++;
    }
    prev = t;
  }

  return (
    <div className="page-container space-y-5">
      <a href="/sessions" id="session-back" className="flex items-center gap-2 text-sm" style={{ color: "var(--brand)" }}>
        <ArrowLeft className="w-4 h-4" /> Back to Sessions
      </a>

      {/* Header */}
      <div className="vigil-card">
        <div className="flex flex-wrap gap-4 items-center justify-between">
          <div>
            <h1 className="text-xl font-bold font-mono" style={{ color: "var(--text-primary)" }}>
              SESSION {session.id.slice(0, 8).toUpperCase()}
            </h1>
            <p className="text-sm mt-0.5" style={{ color: "var(--text-secondary)" }}>
              {session.agent_type} agent · created {timeAgo(session.created_at)}
            </p>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-center">
              <p className="text-xs mb-1" style={{ color: "var(--text-muted)" }}>Status</p>
              <span
                className="text-sm font-semibold capitalize px-2 py-0.5 rounded-full"
                style={{
                  background: session.status === "active" ? "rgba(34,197,94,0.12)" : "var(--bg-elevated)",
                  color: session.status === "active" ? "var(--tier-0)" : "var(--text-muted)",
                }}
              >
                {session.status}
              </span>
            </div>
            <div className="text-center">
              <p className="text-xs mb-1" style={{ color: "var(--text-muted)" }}>Current Tier</p>
              <span className={cn("tier-badge text-sm", `tier-${tier}`)}>
                TIER {tier} — {tierLabel(tier)}
              </span>
            </div>
            <div className="text-center">
              <p className="text-xs mb-1" style={{ color: "var(--text-muted)" }}>Risk Score</p>
              <span className="text-2xl font-bold" style={{ color: tierColor(tier) }}>
                {Math.round(session.current_risk)}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Risk chart */}
      <div className="vigil-card">
        <h2 className="text-sm font-semibold mb-4" style={{ color: "var(--text-secondary)" }}>
          Risk Score Over Time
        </h2>
        <ResponsiveContainer width="100%" height={200}>
          <LineChart data={chartData}>
            <XAxis dataKey="t" tick={{ fontSize: 10, fill: "var(--text-muted)" }} axisLine={false} tickLine={false} />
            <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: "var(--text-muted)" }} axisLine={false} tickLine={false} width={28} />
            <Tooltip
              contentStyle={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)", borderRadius: 8, fontSize: 12 }}
              labelStyle={{ color: "var(--text-secondary)" }}
            />
            {/* Tier boundary dashed lines */}
            <ReferenceLine y={20} stroke="#FACC15" strokeDasharray="4 4" strokeOpacity={0.4} label={{ value: "T1", fill: "#FACC15", fontSize: 10, position: "insideRight" }} />
            <ReferenceLine y={40} stroke="#F97316" strokeDasharray="4 4" strokeOpacity={0.4} label={{ value: "T2", fill: "#F97316", fontSize: 10, position: "insideRight" }} />
            <ReferenceLine y={60} stroke="#EF4444" strokeDasharray="4 4" strokeOpacity={0.4} label={{ value: "T3", fill: "#EF4444", fontSize: 10, position: "insideRight" }} />
            <ReferenceLine y={80} stroke="#7C3AED" strokeDasharray="4 4" strokeOpacity={0.4} label={{ value: "T4", fill: "#7C3AED", fontSize: 10, position: "insideRight" }} />
            <Line
              type="monotone"
              dataKey="risk"
              stroke={tierColor(tier)}
              strokeWidth={2}
              dot={false}
              animationDuration={300}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Tier timeline */}
      {tierSpans.length > 0 && (
        <div className="vigil-card">
          <h2 className="text-sm font-semibold mb-3" style={{ color: "var(--text-secondary)" }}>
            Tier Timeline
          </h2>
          <div className="flex gap-1 h-6 rounded-md overflow-hidden">
            {tierSpans.map((span, i) => (
              <div
                key={i}
                className="flex items-center justify-center text-xs font-bold text-white"
                title={`Tier ${span.tier}: ${span.count} events`}
                style={{
                  background: tierColor(span.tier),
                  flex: span.count,
                  minWidth: 4,
                  opacity: 0.85,
                }}
              >
                {span.count > 1 && `T${span.tier}`}
              </div>
            ))}
          </div>
          <p className="text-xs mt-2" style={{ color: "var(--text-muted)" }}>
            Currently at Tier {tier} — {tierLabel(tier)}
            {tier > 0 && ` · ${5} events required to restore to Tier ${tier - 1}`}
          </p>
        </div>
      )}

      {/* Event feed */}
      <div className="vigil-card">
        <h2 className="text-sm font-semibold mb-3" style={{ color: "var(--text-secondary)" }}>
          Event Feed ({events.length} events)
        </h2>
        {events.length === 0 ? (
          <p className="text-xs text-center py-4" style={{ color: "var(--text-muted)" }}>
            No events recorded yet for this session.
          </p>
        ) : (
          <div className="space-y-1 max-h-80 overflow-y-auto scrollbar-thin">
            {[...events].reverse().map((ev, i) => (
              <div
                key={i}
                className="flex items-center gap-3 px-3 py-2 rounded-lg text-xs fade-in"
                style={{ background: "var(--bg-elevated)" }}
              >
                <span className="w-6 text-right shrink-0" style={{ color: "var(--text-muted)" }}>
                  #{ev.seq_no}
                </span>
                <span className="w-28 font-mono truncate" style={{ color: "var(--brand)" }}>
                  {ev.tool}
                </span>
                <span style={{ color: "var(--text-secondary)" }}>
                  {Math.round(ev.risk_before)}→<span style={{ color: tierColor(ev.tier_after) }}>{Math.round(ev.risk_after)}</span>
                </span>
                <span className={cn("tier-badge", `tier-${ev.tier_after}`)}>T{ev.tier_after}</span>
                <span
                  className="font-semibold"
                  style={{ color: ev.outcome === "allowed" ? "var(--tier-0)" : "var(--tier-3)" }}
                >
                  {ev.outcome?.toUpperCase()}
                </span>
                <span className="ml-auto" style={{ color: "var(--text-muted)" }}>
                  {ev.timestamp ? timeAgo(ev.timestamp) : ""}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
