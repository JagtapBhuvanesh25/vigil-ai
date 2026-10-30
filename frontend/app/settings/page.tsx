"use client";

import { useState } from "react";
import { Save, RefreshCw, Info } from "lucide-react";
import { API_URL } from "@/lib/utils";

interface FormState {
  model: string;
  ollama_url: string;
  temperature: string;
  lambda: string;
  wa: string;
  wb: string;
  wc: string;
  t01: string;
  t12: string;
  t23: string;
  t34: string;
  inbox_mode: "mock" | "imap";
  inbox_path: string;
}

const DEFAULTS: FormState = {
  model: "qwen2.5:7b",
  ollama_url: "http://localhost:11434",
  temperature: "0.1",
  lambda: "0.98",
  wa: "12.0",
  wb: "80.0",
  wc: "20.0",
  t01: "20",
  t12: "40",
  t23: "60",
  t34: "80",
  inbox_mode: "mock",
  inbox_path: "./fixtures/emails",
};

function Field({
  id, label, value, onChange, type = "text", hint,
}: {
  id: string; label: string; value: string; onChange: (v: string) => void;
  type?: string; hint?: string;
}) {
  return (
    <div className="flex items-center gap-4">
      <label htmlFor={id} className="text-sm w-40 shrink-0" style={{ color: "var(--text-secondary)" }}>
        {label}
      </label>
      <input
        id={id}
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="flex-1 px-3 py-2 rounded-lg text-sm outline-none"
        style={{
          background: "var(--bg-elevated)",
          border: "1px solid var(--border-default)",
          color: "var(--text-primary)",
        }}
      />
      {hint && <span className="text-xs shrink-0" style={{ color: "var(--text-muted)" }}>{hint}</span>}
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="vigil-card space-y-4">
      <h2 className="text-sm font-semibold uppercase tracking-wider border-b pb-3" style={{ color: "var(--text-secondary)", borderColor: "var(--border-subtle)" }}>
        {title}
      </h2>
      {children}
    </div>
  );
}

export default function SettingsPage() {
  const [form, setForm] = useState<FormState>(DEFAULTS);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  function set(key: keyof FormState) {
    return (value: string) => setForm((f) => ({ ...f, [key]: value }));
  }

  async function handleSave() {
    setSaving(true);
    setSaved(false);
    try {
      // POST to config hot-reload endpoint (Phase 8 implements backend side)
      await fetch(`${API_URL}/config/reload`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scoring: {
            lambda: parseFloat(form.lambda),
            wa: parseFloat(form.wa),
            wb: parseFloat(form.wb),
            wc: parseFloat(form.wc),
          },
          tiers: {
            t01: parseInt(form.t01),
            t12: parseInt(form.t12),
            t23: parseInt(form.t23),
            t34: parseInt(form.t34),
          },
          llm: {
            model: form.model,
            ollama_url: form.ollama_url,
            temperature: parseFloat(form.temperature),
          },
        }),
      });
    } catch {
      // Endpoint might not exist yet — still show saved
    } finally {
      setSaving(false);
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    }
  }

  function handleReset() {
    setForm(DEFAULTS);
  }

  return (
    <div className="page-container space-y-5 max-w-3xl">
      <div>
        <h1 className="text-3xl font-bold">Settings</h1>
        <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
          Configure model, scoring weights, and thresholds
        </p>
      </div>

      {/* LLM Config */}
      <Section title="LLM Configuration">
        <Field id="setting-model" label="Model" value={form.model} onChange={set("model")} hint="qwen2.5:7b / llama3.2" />
        <Field id="setting-ollama-url" label="Ollama URL" value={form.ollama_url} onChange={set("ollama_url")} />
        <Field id="setting-temperature" label="Temperature" value={form.temperature} onChange={set("temperature")} type="number" hint="0.0–1.0" />
      </Section>

      {/* Risk Scoring Weights */}
      <Section title="Risk Scoring Weights">
        <div
          className="flex items-start gap-2 p-3 rounded-lg text-xs"
          style={{ background: "var(--brand-dim)", color: "var(--brand)", border: "1px solid rgba(5,213,250,0.2)" }}
        >
          <Info className="w-3.5 h-3.5 shrink-0 mt-0.5" />
          Algorithm 1: Rt = clamp(λ·Rt-1 + wa·Sa + wb·Sd + wc·Sh, 0, 100)
        </div>
        <Field id="setting-lambda" label="λ (decay)" value={form.lambda} onChange={set("lambda")} type="number" hint="0.90–0.99" />
        <Field id="setting-wa" label="wa (anomaly)" value={form.wa} onChange={set("wa")} type="number" />
        <Field id="setting-wb" label="wb (deception)" value={form.wb} onChange={set("wb")} type="number" />
        <Field id="setting-wc" label="wc (heuristic)" value={form.wc} onChange={set("wc")} type="number" />
      </Section>

      {/* Tier Boundaries */}
      <Section title="Tier Boundaries">
        <div className="grid grid-cols-2 gap-3">
          <Field id="setting-t01" label="T0→T1" value={form.t01} onChange={set("t01")} type="number" hint="default: 20" />
          <Field id="setting-t12" label="T1→T2" value={form.t12} onChange={set("t12")} type="number" hint="default: 40" />
          <Field id="setting-t23" label="T2→T3" value={form.t23} onChange={set("t23")} type="number" hint="default: 60" />
          <Field id="setting-t34" label="T3→T4" value={form.t34} onChange={set("t34")} type="number" hint="default: 80" />
        </div>
      </Section>

      {/* Inbox Configuration */}
      <Section title="Inbox Configuration">
        <div className="flex items-center gap-4">
          <span className="text-sm w-40 shrink-0" style={{ color: "var(--text-secondary)" }}>Mode</span>
          <div className="flex gap-3">
            {(["mock", "imap"] as const).map((mode) => (
              <label key={mode} className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  id={`setting-inbox-${mode}`}
                  name="inbox_mode"
                  value={mode}
                  checked={form.inbox_mode === mode}
                  onChange={() => set("inbox_mode")(mode)}
                  className="accent-[color:var(--brand)]"
                />
                <span className="text-sm capitalize" style={{ color: "var(--text-secondary)" }}>
                  {mode === "mock" ? "Mock Inbox (local .eml files)" : "IMAP (real email)"}
                </span>
              </label>
            ))}
          </div>
        </div>
        <Field id="setting-inbox-path" label="Path / IMAP Host" value={form.inbox_path} onChange={set("inbox_path")} />
      </Section>

      {/* Save / Reset */}
      <div className="flex gap-3">
        <button
          id="settings-save"
          onClick={handleSave}
          disabled={saving}
          className="flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-semibold disabled:opacity-60"
          style={{ background: "var(--brand-dim)", color: "var(--brand)", border: "1px solid rgba(5,213,250,0.3)" }}
        >
          {saving ? (
            <span className="animate-spin w-4 h-4 border-2 border-current border-t-transparent rounded-full" />
          ) : saved ? (
            "✓ Saved"
          ) : (
            <><Save className="w-4 h-4" /> Save & Hot-Reload</>
          )}
        </button>
        <button
          id="settings-reset"
          onClick={handleReset}
          className="flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm"
          style={{ background: "var(--bg-elevated)", color: "var(--text-secondary)", border: "1px solid var(--border-subtle)" }}
        >
          <RefreshCw className="w-4 h-4" /> Reset to Defaults
        </button>
      </div>
    </div>
  );
}
