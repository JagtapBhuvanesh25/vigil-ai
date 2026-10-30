"use client";

import { useEffect, useState } from "react";
import { Plus, Download, Trash2, RefreshCw, ChevronDown, ChevronRight } from "lucide-react";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  LineChart, Line,
} from "recharts";
import { api } from "@/lib/api";
import type { ThreatEntry } from "@/lib/api";
import { cn, timeAgo } from "@/lib/utils";

function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const color = pct > 80 ? "var(--tier-3)" : pct > 50 ? "var(--tier-2)" : "var(--tier-1)";
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 rounded-full" style={{ background: "var(--bg-base)" }}>
        <div className="h-full rounded-full" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="text-xs tabular-nums" style={{ color: "var(--text-secondary)" }}>{pct}%</span>
    </div>
  );
}

function ThreatTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    prompt_injection: "var(--tier-3)",
    behavioral_anomaly: "var(--tier-2)",
    honeytoken_interaction: "var(--tier-4)",
    composite: "var(--brand)",
    manual: "var(--text-secondary)",
  };
  const color = map[type] ?? "var(--text-muted)";
  return (
    <span className="text-xs px-2 py-0.5 rounded" style={{ background: `${color}18`, color, border: `1px solid ${color}30` }}>
      {type.replace(/_/g, " ")}
    </span>
  );
}

export default function ThreatIntelPage() {
  const [entries, setEntries] = useState<ThreatEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [addUrl, setAddUrl] = useState("");
  const [adding, setAdding] = useState(false);

  async function load() {
    setLoading(true);
    try {
      const res = await api.threatIntel.list({ active_only: false });
      setEntries(res.entries ?? []);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  const active = entries.filter((e) => e.is_active);
  const domains = [...new Set(active.map((e) => e.domain))];

  async function handleRemove(id: string) {
    if (!confirm("Remove this entry from the blacklist?")) return;
    await api.threatIntel.remove(id);
    await load();
  }

  async function handleAdd() {
    if (!addUrl.trim()) return;
    setAdding(true);
    try {
      await api.threatIntel.add(addUrl.trim());
      setAddUrl("");
      await load();
    } finally {
      setAdding(false);
    }
  }

  async function handleExport(format: "json" | "csv") {
    const res = await api.threatIntel.export(format);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `threat-intel.${format}`;
    a.click();
    URL.revokeObjectURL(url);
  }

  // Threat type breakdown for chart
  const typeCount: Record<string, number> = {};
  active.forEach((e) => { typeCount[e.threat_type] = (typeCount[e.threat_type] ?? 0) + 1; });
  const typeChartData = Object.entries(typeCount).map(([name, value]) => ({
    name: name.replace(/_/g, " "),
    value,
  }));

  return (
    <div className="page-container space-y-5">
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-3xl font-bold">Threat Intelligence</h1>
          <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
            {active.length} active entries · {domains.length} domains blocked
          </p>
        </div>
        <div className="flex gap-2 flex-wrap">
          <button id="threat-export-json" onClick={() => handleExport("json")}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm"
            style={{ background: "var(--bg-elevated)", color: "var(--text-secondary)", border: "1px solid var(--border-subtle)" }}>
            <Download className="w-4 h-4" /> JSON
          </button>
          <button id="threat-export-csv" onClick={() => handleExport("csv")}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm"
            style={{ background: "var(--bg-elevated)", color: "var(--text-secondary)", border: "1px solid var(--border-subtle)" }}>
            <Download className="w-4 h-4" /> CSV
          </button>
          <button id="threat-refresh" onClick={load}
            className="p-2 rounded-lg"
            style={{ background: "var(--bg-elevated)", color: "var(--text-secondary)", border: "1px solid var(--border-subtle)" }}>
            <RefreshCw className={cn("w-4 h-4", loading && "animate-spin")} />
          </button>
        </div>
      </div>

      {/* Overview cards */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: "Active Blacklist", value: active.length, color: "var(--tier-3)" },
          { label: "Domains Blocked", value: domains.length, color: "var(--tier-4)" },
          { label: "Total Entries", value: entries.length, color: "var(--brand)" },
        ].map(({ label, value, color }) => (
          <div key={label} className="vigil-card text-center">
            <p className="text-xs mb-2" style={{ color: "var(--text-secondary)" }}>{label}</p>
            <p className="text-3xl font-bold" style={{ color }}>{value}</p>
          </div>
        ))}
      </div>

      {/* Charts row */}
      {typeChartData.length > 0 && (
        <div className="vigil-card">
          <h2 className="text-sm font-semibold mb-4" style={{ color: "var(--text-secondary)" }}>
            Threat Type Breakdown
          </h2>
          <ResponsiveContainer width="100%" height={140}>
            <BarChart data={typeChartData} layout="vertical">
              <XAxis type="number" tick={{ fontSize: 10, fill: "var(--text-muted)" }} axisLine={false} tickLine={false} />
              <YAxis dataKey="name" type="category" width={140} tick={{ fontSize: 11, fill: "var(--text-secondary)" }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)", borderRadius: 8, fontSize: 12 }} />
              <Bar dataKey="value" fill="var(--tier-3)" radius={4} maxBarSize={16} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Add URL */}
      <div className="vigil-card">
        <h2 className="text-sm font-semibold mb-3" style={{ color: "var(--text-secondary)" }}>
          Add URL to Blacklist
        </h2>
        <div className="flex gap-2">
          <input
            id="threat-add-url"
            value={addUrl}
            onChange={(e) => setAddUrl(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleAdd()}
            placeholder="https://malicious-site.example.com"
            className="flex-1 px-3 py-2 rounded-lg text-sm outline-none"
            style={{ background: "var(--bg-elevated)", border: "1px solid var(--border-default)", color: "var(--text-primary)" }}
          />
          <button
            id="threat-add-btn"
            onClick={handleAdd}
            disabled={adding || !addUrl.trim()}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold disabled:opacity-50"
            style={{ background: "var(--brand-dim)", color: "var(--brand)", border: "1px solid rgba(5,213,250,0.3)" }}
          >
            {adding ? <span className="animate-spin w-4 h-4 border-2 border-current border-t-transparent rounded-full" /> : <Plus className="w-4 h-4" />}
            Add
          </button>
        </div>
      </div>

      {/* Blacklist table */}
      <div className="vigil-card p-0 overflow-hidden">
        <div className="px-5 py-4 border-b" style={{ borderColor: "var(--border-subtle)" }}>
          <h2 className="text-sm font-semibold" style={{ color: "var(--text-secondary)" }}>
            Active Blacklist
          </h2>
        </div>
        {loading ? (
          <div className="p-8 text-center text-sm" style={{ color: "var(--text-muted)" }}>Loading…</div>
        ) : active.length === 0 ? (
          <div className="p-8 text-center text-sm" style={{ color: "var(--text-muted)" }}>No blacklisted entries yet.</div>
        ) : (
          <div className="divide-y" style={{ borderColor: "var(--border-subtle)" }}>
            {active.map((entry) => (
              <div key={entry.id}>
                <div
                  className="flex items-center gap-4 px-5 py-4 cursor-pointer"
                  style={{ borderLeft: entry.domain && !entry.url.includes("/") ? "3px solid var(--tier-4)" : undefined }}
                  onClick={() => setExpanded(expanded === entry.id ? null : entry.id)}
                  onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "var(--bg-elevated)"; }}
                  onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = ""; }}
                >
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-mono truncate" style={{ color: "var(--text-primary)" }}>
                      {entry.url}
                      {!entry.url.includes("/") && (
                        <span className="ml-2 text-xs" style={{ color: "var(--tier-4)" }}>(DOMAIN)</span>
                      )}
                    </p>
                  </div>
                  <ThreatTypeBadge type={entry.threat_type} />
                  <ConfidenceBar value={entry.confidence} />
                  <span className="text-xs shrink-0 w-16 text-right" style={{ color: "var(--text-muted)" }}>
                    {timeAgo(entry.last_triggered)}
                  </span>
                  <button
                    id={`threat-remove-${entry.id}`}
                    onClick={(e) => { e.stopPropagation(); handleRemove(entry.id); }}
                    className="p-1.5 rounded-md transition-colors"
                    style={{ color: "var(--text-muted)" }}
                    title="Remove from blacklist"
                    onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.color = "var(--tier-3)"; }}
                    onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.color = "var(--text-muted)"; }}
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                  {expanded === entry.id ? <ChevronDown className="w-4 h-4 shrink-0" style={{ color: "var(--text-muted)" }} /> : <ChevronRight className="w-4 h-4 shrink-0" style={{ color: "var(--text-muted)" }} />}
                </div>
                {expanded === entry.id && (
                  <div className="px-5 pb-4 text-xs space-y-2 fade-in" style={{ background: "var(--bg-elevated)", color: "var(--text-secondary)" }}>
                    <p><span style={{ color: "var(--text-muted)" }}>Domain:</span> {entry.domain}</p>
                    <p><span style={{ color: "var(--text-muted)" }}>First seen:</span> {new Date(entry.first_seen).toLocaleString()}</p>
                    <p><span style={{ color: "var(--text-muted)" }}>Last triggered:</span> {new Date(entry.last_triggered).toLocaleString()}</p>
                    <p><span style={{ color: "var(--text-muted)" }}>Trigger count:</span> {entry.trigger_count}</p>
                    {entry.flagging_session_id && (
                      <p>
                        <span style={{ color: "var(--text-muted)" }}>Flagged by session: </span>
                        <a href={`/sessions/${entry.flagging_session_id}`} style={{ color: "var(--brand)" }}>
                          {entry.flagging_session_id.slice(0, 8)}…
                        </a>
                      </p>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
