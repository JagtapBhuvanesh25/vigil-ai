"use client";

import { useEffect, useState } from "react";
import {
  Mail, ShieldOff, Globe, Activity,
  CheckCircle, XCircle, Minus, TrendingUp,
} from "lucide-react";
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from "recharts";
import { api } from "@/lib/api";
import type { Session, Email } from "@/lib/api";
import { cn, timeAgo, tierColor, tierLabel, classificationClass } from "@/lib/utils";

// ── Stat card ────────────────────────────────────────────────────────────────
function StatCard({
  id, icon: Icon, label, value, sub, color,
}: {
  id: string;
  icon: React.ElementType;
  label: string;
  value: number | string;
  sub?: string;
  color?: string;
}) {
  return (
    <div
      id={id}
      className="vigil-card flex flex-col gap-3 transition-all duration-200"
      style={{ borderColor: color ? `${color}30` : undefined }}
      onMouseEnter={(e) => {
        if (color) (e.currentTarget as HTMLElement).style.boxShadow = `0 0 20px ${color}15`;
      }}
      onMouseLeave={(e) => {
        (e.currentTarget as HTMLElement).style.boxShadow = "";
      }}
    >
      <div className="flex items-center justify-between">
        <span className="text-sm" style={{ color: "var(--text-secondary)" }}>{label}</span>
        <div
          className="w-8 h-8 rounded-lg flex items-center justify-center"
          style={{ background: color ? `${color}18` : "var(--bg-elevated)" }}
        >
          <Icon className="w-4 h-4" style={{ color: color ?? "var(--brand)" }} />
        </div>
      </div>
      <div>
        <span className="text-3xl font-bold" style={{ color: "var(--text-primary)" }}>
          {value}
        </span>
      </div>
      {sub && (
        <span className="text-xs flex items-center gap-1" style={{ color: "var(--text-muted)" }}>
          <TrendingUp className="w-3 h-3" style={{ color: "var(--tier-0)" }} />
          {sub}
        </span>
      )}
    </div>
  );
}

// ── System health strip ──────────────────────────────────────────────────────
function HealthItem({ label, ok }: { label: string; ok: boolean | null }) {
  return (
    <div className="flex items-center gap-1.5">
      {ok === null
        ? <Minus className="w-3 h-3" style={{ color: "var(--text-muted)" }} />
        : ok
        ? <CheckCircle className="w-3 h-3" style={{ color: "var(--tier-0)" }} />
        : <XCircle className="w-3 h-3" style={{ color: "var(--tier-3)" }} />
      }
      <span className="text-xs" style={{ color: ok ? "var(--text-secondary)" : "var(--tier-3)" }}>
        {label}
      </span>
    </div>
  );
}

// ── Main client component ────────────────────────────────────────────────────
export function DashboardClient() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [emails, setEmails] = useState<Email[]>([]);
  const [health, setHealth] = useState<Record<string, { status: string }>>({});
  const [loading, setLoading] = useState(true);

  async function fetchAll() {
    try {
      const [sessRes, emlRes, hRes] = await Promise.allSettled([
        api.sessions.list(),
        api.emails.list({ page: 1 }),
        api.health(),
      ]);
      if (sessRes.status === "fulfilled") setSessions(sessRes.value.sessions ?? []);
      if (emlRes.status === "fulfilled") setEmails(emlRes.value.emails ?? []);
      if (hRes.status === "fulfilled") setHealth(hRes.value.components ?? {});
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchAll();
    const id = setInterval(fetchAll, 10_000);
    return () => clearInterval(id);
  }, []);

  const totalEmails = emails.length;
  const threatsBlocked = emails.filter(
    (e) => e.classification === "malicious" || e.classification === "honeytoken"
  ).length;
  const activeSessions = sessions.filter((s) => s.status === "active").length;
  const suspiciousEmails = emails.filter((e) => e.classification === "suspicious").length;

  // Chart data: risk score over last sessions
  const chartData = sessions.slice(0, 20).reverse().map((s, i) => ({
    t: `S${i + 1}`,
    risk: Math.round(s.current_risk),
    tier: s.current_tier,
  }));

  // Threat type breakdown pie
  const typeMap: Record<string, number> = {
    Malicious: emails.filter((e) => e.classification === "malicious").length,
    Suspicious: emails.filter((e) => e.classification === "suspicious").length,
    Honeytoken: emails.filter((e) => e.classification === "honeytoken").length,
    Safe: emails.filter((e) => e.classification === "safe").length,
  };
  const pieData = Object.entries(typeMap)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }));
  const pieColors = ["#EF4444", "#FACC15", "#7C3AED", "#22C55E"];

  // Recent threats feed
  const recentThreats = emails
    .filter((e) => e.classification !== "safe" && e.classification !== "pending")
    .slice(0, 8);

  return (
    <div className="page-container space-y-6">
      {/* Page header */}
      <div>
        <h1 className="text-3xl font-bold" style={{ color: "var(--text-primary)" }}>
          Dashboard
        </h1>
        <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
          Situational awareness — live threat monitoring
        </p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          id="stat-total-emails"
          icon={Mail}
          label="Total Emails"
          value={loading ? "—" : totalEmails}
          sub={`${suspiciousEmails} suspicious`}
          color="var(--brand)"
        />
        <StatCard
          id="stat-threats-blocked"
          icon={ShieldOff}
          label="Threats Blocked"
          value={loading ? "—" : threatsBlocked}
          sub="malicious + honeytoken"
          color="var(--tier-3)"
        />
        <StatCard
          id="stat-urls-blocked"
          icon={Globe}
          label="Domains Blocked"
          value="—"
          sub="visit Threat Intel"
          color="var(--tier-2)"
        />
        <StatCard
          id="stat-active-sessions"
          icon={Activity}
          label="Active Sessions"
          value={loading ? "—" : activeSessions}
          sub={`${sessions.length} total`}
          color="var(--tier-0)"
        />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Risk activity chart */}
        <div className="lg:col-span-2 vigil-card">
          <h2 className="text-sm font-semibold mb-4" style={{ color: "var(--text-secondary)" }}>
            Risk Score Activity (Sessions)
          </h2>
          {chartData.length > 0 ? (
            <ResponsiveContainer width="100%" height={180}>
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--brand)" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="var(--brand)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="t" tick={{ fontSize: 11, fill: "var(--text-muted)" }} axisLine={false} tickLine={false} />
                <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: "var(--text-muted)" }} axisLine={false} tickLine={false} width={30} />
                <Tooltip
                  contentStyle={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)", borderRadius: 8, fontSize: 12 }}
                  labelStyle={{ color: "var(--text-secondary)" }}
                  itemStyle={{ color: "var(--brand)" }}
                />
                {/* Tier boundary lines */}
                {[20, 40, 60, 80].map((y, i) => (
                  <line key={y} x1="0" x2="100%" y1={`${100 - y}%`} y2={`${100 - y}%`}
                    stroke={["#FACC15","#F97316","#EF4444","#7C3AED"][i]}
                    strokeDasharray="4 4" strokeOpacity={0.35} strokeWidth={1}
                  />
                ))}
                <Area type="monotone" dataKey="risk" stroke="var(--brand)" strokeWidth={2} fill="url(#riskGrad)" dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-44 flex items-center justify-center text-sm" style={{ color: "var(--text-muted)" }}>
              No session data yet
            </div>
          )}
        </div>

        {/* Threat breakdown pie */}
        <div className="vigil-card">
          <h2 className="text-sm font-semibold mb-4" style={{ color: "var(--text-secondary)" }}>
            Threat Breakdown
          </h2>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={50} outerRadius={75} paddingAngle={3} dataKey="value">
                  {pieData.map((_, i) => (
                    <Cell key={i} fill={pieColors[i % pieColors.length]} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)", borderRadius: 8, fontSize: 12 }} />
                <Legend
                  iconType="circle"
                  iconSize={8}
                  formatter={(value) => <span style={{ color: "var(--text-secondary)", fontSize: 11 }}>{value}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-44 flex items-center justify-center text-sm" style={{ color: "var(--text-muted)" }}>
              No data yet
            </div>
          )}
        </div>
      </div>

      {/* Bottom row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Recent threats feed */}
        <div className="vigil-card">
          <h2 className="text-sm font-semibold mb-3" style={{ color: "var(--text-secondary)" }}>
            Recent Threats
          </h2>
          <div className="space-y-2">
            {recentThreats.length === 0 ? (
              <p className="text-xs py-4 text-center" style={{ color: "var(--text-muted)" }}>
                No threats detected yet
              </p>
            ) : (
              recentThreats.map((e) => (
                <a
                  key={e.id}
                  href={`/inbox/${e.id}`}
                  className="flex items-center gap-3 p-2.5 rounded-lg transition-colors hover:opacity-80 fade-in"
                  style={{ background: "var(--bg-elevated)" }}
                >
                  <span className={cn("tier-badge", classificationClass(e.classification))}>
                    ● {e.classification.toUpperCase()}
                  </span>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-medium truncate" style={{ color: "var(--text-primary)" }}>
                      {e.sender || "unknown sender"}
                    </p>
                    <p className="text-xs truncate" style={{ color: "var(--text-muted)" }}>
                      {e.subject || "(no subject)"}
                    </p>
                  </div>
                  <span className="text-xs shrink-0" style={{ color: "var(--text-muted)" }}>
                    {timeAgo(e.created_at)}
                  </span>
                </a>
              ))
            )}
          </div>
        </div>

        {/* System health */}
        <div className="vigil-card">
          <h2 className="text-sm font-semibold mb-3" style={{ color: "var(--text-secondary)" }}>
            System Health
          </h2>
          <div className="space-y-3">
            {[
              { label: "Database", key: "database" },
              { label: "Ollama LLM", key: "ollama" },
              { label: "Docker Adapter", key: "docker" },
              { label: "Audit Chain", key: "audit" },
            ].map(({ label, key }) => (
              <div key={key} className="flex items-center justify-between py-1 border-b" style={{ borderColor: "var(--border-subtle)" }}>
                <HealthItem
                  label={label}
                  ok={loading ? null : health[key]?.status === "ok" ? true : health[key] ? false : null}
                />
                <span className="text-xs" style={{ color: "var(--text-muted)" }}>
                  {loading ? "checking…" : health[key]?.status ?? "unknown"}
                </span>
              </div>
            ))}
            {/* Active sessions */}
            <div className="mt-2 p-3 rounded-lg" style={{ background: "var(--bg-elevated)" }}>
              {sessions.slice(0, 3).map((s) => (
                <div key={s.id} className="flex items-center gap-2 py-1">
                  <span
                    className="w-2 h-2 rounded-full shrink-0"
                    style={{ background: tierColor(s.current_tier) }}
                  />
                  <a href={`/sessions/${s.id}`} className="text-xs hover:underline truncate" style={{ color: "var(--text-secondary)" }}>
                    {s.id.slice(0, 8)}…
                  </a>
                  <span className={cn("tier-badge ml-auto", `tier-${s.current_tier}`)}>
                    T{s.current_tier}
                  </span>
                  <span className="text-xs" style={{ color: "var(--text-muted)" }}>
                    {tierLabel(s.current_tier)}
                  </span>
                </div>
              ))}
              {sessions.length === 0 && (
                <p className="text-xs" style={{ color: "var(--text-muted)" }}>No active sessions</p>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
