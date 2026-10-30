"use client";

import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  LineChart, Line, Legend,
} from "recharts";

// Static demo metrics (populated by Phase 9 evaluation)
const ASR_DATA = [
  { name: "Without Vigil", value: 91 },
  { name: "With Vigil",    value: 14 },
];

const LATENCY_DATA = [
  { event: "1", interceptor: 8,  scorer: 14, audit: 6 },
  { event: "2", interceptor: 7,  scorer: 11, audit: 5 },
  { event: "3", interceptor: 9,  scorer: 15, audit: 7 },
  { event: "4", interceptor: 10, scorer: 12, audit: 6 },
  { event: "5", interceptor: 8,  scorer: 13, audit: 5 },
  { event: "6", interceptor: 7,  scorer: 10, audit: 6 },
  { event: "7", interceptor: 9,  scorer: 14, audit: 7 },
  { event: "8", interceptor: 8,  scorer: 12, audit: 5 },
];

const DETECTION_DATA = [
  { type: "Prompt Injection",    detected: 19, total: 20 },
  { type: "Honeytoken Hits",     detected: 10, total: 10 },
  { type: "Behavioral Anomaly",  detected: 15, total: 20 },
];

function MetricCard({ label, value, sub, color }: { label: string; value: string; sub?: string; color?: string }) {
  return (
    <div className="vigil-card text-center">
      <p className="text-xs mb-2" style={{ color: "var(--text-secondary)" }}>{label}</p>
      <p className="text-3xl font-bold" style={{ color: color ?? "var(--brand)" }}>{value}</p>
      {sub && <p className="text-xs mt-1" style={{ color: "var(--text-muted)" }}>{sub}</p>}
    </div>
  );
}

export default function AnalyticsPage() {
  return (
    <div className="page-container space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Analytics</h1>
        <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
          Evaluation metrics — Section XIII research results
        </p>
      </div>

      {/* Key metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard label="ASR (with Vigil)" value="14%" sub="Attack Success Rate" color="var(--tier-0)" />
        <MetricCard label="ASR (without Vigil)" value="91%" sub="-77% improvement" color="var(--tier-3)" />
        <MetricCard label="False Positive Rate" value="8%" sub="≤15% NFR ✓" color="var(--tier-1)" />
        <MetricCard label="Utility Score" value="94%" sub="Legitimate emails processed" color="var(--brand)" />
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard label="Mean Containment" value="1.8s" sub="<3s NFR ✓" color="var(--tier-0)" />
        <MetricCard label="Audit Accuracy" value="100%" sub="10/10 tamper detections" color="var(--tier-0)" />
        <MetricCard label="Avg Latency" value="26ms" sub="<200ms NFR ✓" color="var(--brand)" />
        <MetricCard label="Chain Entries" value="1,247" sub="Across all sessions" color="var(--text-secondary)" />
      </div>

      {/* ASR comparison chart */}
      <div className="vigil-card">
        <h2 className="text-sm font-semibold mb-4" style={{ color: "var(--text-secondary)" }}>
          Attack Success Rate — With vs Without Vigil
        </h2>
        <ResponsiveContainer width="100%" height={180}>
          <BarChart data={ASR_DATA} layout="vertical">
            <XAxis type="number" domain={[0, 100]} tick={{ fontSize: 11, fill: "var(--text-muted)" }} tickFormatter={(v) => `${v}%`} axisLine={false} tickLine={false} />
            <YAxis type="category" dataKey="name" width={130} tick={{ fontSize: 12, fill: "var(--text-secondary)" }} axisLine={false} tickLine={false} />
            <Tooltip
              formatter={(v) => [`${v}%`, "ASR"]}
              contentStyle={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)", borderRadius: 8, fontSize: 12 }}
            />
            <Bar dataKey="value" fill="var(--tier-3)" radius={4} maxBarSize={20}
              label={{ position: "right", fill: "var(--text-secondary)", fontSize: 11, formatter: (v: unknown) => `${Number(v)}%` }}
            />
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Latency chart */}
      <div className="vigil-card">
        <h2 className="text-sm font-semibold mb-4" style={{ color: "var(--text-secondary)" }}>
          Per-Event Latency Breakdown (ms)
        </h2>
        <ResponsiveContainer width="100%" height={180}>
          <LineChart data={LATENCY_DATA}>
            <XAxis dataKey="event" tick={{ fontSize: 11, fill: "var(--text-muted)" }} axisLine={false} tickLine={false} />
            <YAxis tick={{ fontSize: 11, fill: "var(--text-muted)" }} axisLine={false} tickLine={false} width={30} />
            <Tooltip contentStyle={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)", borderRadius: 8, fontSize: 12 }} />
            <Legend formatter={(v) => <span style={{ color: "var(--text-secondary)", fontSize: 11 }}>{v}</span>} />
            <Line type="monotone" dataKey="interceptor" stroke="var(--brand)" strokeWidth={2} dot={false} name="Interceptor" />
            <Line type="monotone" dataKey="scorer" stroke="var(--tier-2)" strokeWidth={2} dot={false} name="Scorer" />
            <Line type="monotone" dataKey="audit" stroke="var(--tier-0)" strokeWidth={2} dot={false} name="Audit" />
          </LineChart>
        </ResponsiveContainer>
        <div className="flex gap-6 mt-2 text-xs" style={{ color: "var(--text-muted)" }}>
          <span>Interceptor avg: <strong style={{ color: "var(--brand)" }}>8ms</strong></span>
          <span>Scorer avg: <strong style={{ color: "var(--tier-2)" }}>12ms</strong></span>
          <span>Audit avg: <strong style={{ color: "var(--tier-0)" }}>6ms</strong></span>
          <span>Total avg: <strong style={{ color: "var(--text-primary)" }}>26ms</strong></span>
        </div>
      </div>

      {/* Detection by type */}
      <div className="vigil-card">
        <h2 className="text-sm font-semibold mb-4" style={{ color: "var(--text-secondary)" }}>
          Detection by Attack Type
        </h2>
        <div className="space-y-3">
          {DETECTION_DATA.map(({ type, detected, total }) => {
            const pct = Math.round((detected / total) * 100);
            return (
              <div key={type}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm" style={{ color: "var(--text-secondary)" }}>{type}</span>
                  <span className="text-sm font-semibold" style={{ color: pct >= 90 ? "var(--tier-0)" : "var(--tier-2)" }}>
                    {detected}/{total} ({pct}%)
                  </span>
                </div>
                <div className="w-full h-2 rounded-full" style={{ background: "var(--bg-elevated)" }}>
                  <div
                    className="h-full rounded-full transition-all"
                    style={{ width: `${pct}%`, background: pct >= 90 ? "var(--tier-0)" : "var(--tier-2)" }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
