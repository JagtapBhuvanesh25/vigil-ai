/**
 * lib/api.ts — Typed API client for Vigil AI backend.
 *
 * All fetch calls live here. Components import typed functions, not raw URLs.
 */

import { API_URL } from "./utils";

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`GET ${path} → ${res.status}`);
  return res.json() as Promise<T>;
}

async function post<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`POST ${path} → ${res.status}`);
  return res.json() as Promise<T>;
}

// ── Types ──────────────────────────────────────────────────────────────────

export interface HealthResponse {
  status: string;
  components: Record<string, { status: string; detail?: string }>;
}

export interface Session {
  id: string;
  created_at: string;
  updated_at?: string;
  status: string;
  current_tier: number;
  current_risk: number;
  agent_type: string;
  events?: SessionEvent[];
}

export interface SessionEvent {
  seq_no: number;
  tool: string;
  risk_before: number;
  risk_after: number;
  tier_before: number;
  tier_after: number;
  outcome: "allowed" | "denied";
  timestamp: string;
  signals?: { heuristic: number; anomaly: number; deception: number };
}

export interface Email {
  id: string;
  session_id: string;
  message_id: string;
  subject: string;
  sender: string;
  received_at: string | null;
  classification: string;
  confidence: number;
  verdict_json: string | null;
  risk_score: number;
  created_at: string;
}

export interface Verdict {
  verdict: string;
  confidence: number;
  reasoning: string[];
  iocs?: { urls: string[]; headers: string[] };
}

export interface AuditEntry {
  id: number;
  session_id: string;
  seq_no: number;
  event_type: string;
  payload_json: string;
  prev_hash: string;
  entry_hash: string;
  created_at: string;
}

export interface AuditListResponse {
  total: number;
  page: number;
  page_size: number;
  entries: AuditEntry[];
}

export interface VerifyResponse {
  valid: boolean;
  tampered_session: string | null;
  tampered_at_seq: number | null;
  total_verified: number;
  error?: string;
}

export interface ThreatEntry {
  id: string;
  url: string;
  domain: string;
  threat_type: string;
  confidence: number;
  first_seen: string;
  last_triggered: string;
  trigger_count: number;
  is_active: boolean;
  flagging_session_id: string | null;
}

export interface ThreatListResponse {
  total: number;
  active: number;
  entries: ThreatEntry[];
}

export interface Escalation {
  id: string;
  session_id: string;
  triggered_at: string;
  resolved_at: string | null;
  resolved_by: string | null;
  resolution: string | null;
  context: Record<string, unknown>;
  is_pending: boolean;
}

export interface EscalationsResponse {
  pending_count: number;
  resolved_count: number;
  pending: Escalation[];
  resolved: Escalation[];
}

// ── Health ─────────────────────────────────────────────────────────────────

export const api = {
  health: () => get<HealthResponse>("/health"),

  // Sessions
  sessions: {
    list: () => get<{ sessions: Session[] }>("/sessions"),
    get: (id: string) => get<Session>(`/sessions/${id}`),
    create: (agent_type = "email") => post<Session>("/sessions", { agent_type }),
  },

  // Emails
  emails: {
    list: (params?: { classification?: string; page?: number }) => {
      const qs = new URLSearchParams();
      if (params?.classification) qs.set("classification", params.classification);
      if (params?.page) qs.set("page", String(params.page));
      const q = qs.toString() ? `?${qs}` : "";
      return get<{ total: number; emails: Email[] }>(`/emails${q}`);
    },
    get: (id: string) => get<Email & { verdict?: Verdict }>(`/emails/${id}`),
    analyze: (id: string) => post<{ email_id: string; status: string }>(`/emails/analyze`, { email_id: id }),
  },

  // Audit
  audit: {
    list: (params?: { session_id?: string; page?: number; page_size?: number }) => {
      const qs = new URLSearchParams();
      if (params?.session_id) qs.set("session_id", params.session_id);
      if (params?.page) qs.set("page", String(params.page));
      if (params?.page_size) qs.set("page_size", String(params.page_size));
      const q = qs.toString() ? `?${qs}` : "";
      return get<AuditListResponse>(`/audit${q}`);
    },
    bySession: (id: string) => get<{ session_id: string; count: number; entries: AuditEntry[] }>(`/audit/${id}`),
    verify: (session_id?: string) => {
      const q = session_id ? `?session_id=${session_id}` : "";
      return post<VerifyResponse>(`/audit/verify${q}`);
    },
  },

  // Threat Intel
  threatIntel: {
    list: (params?: { active_only?: boolean }) => {
      const q = params?.active_only ? "?active_only=true" : "";
      return get<ThreatListResponse>(`/threat-intel${q}`);
    },
    remove: (id: string) => post<{ id: string; status: string }>(`/threat-intel/${id}/deactivate`),
    add: (url: string, threat_type = "manual") =>
      post<ThreatEntry>("/threat-intel/override", { url, threat_type, confidence: 0.99 }),
    export: (format: "json" | "csv") =>
      fetch(`${API_URL}/threat-intel/export?format=${format}`),
  },

  // Escalations
  escalations: {
    list: () => get<EscalationsResponse>("/escalations"),
    get: (id: string) => get<Escalation>(`/escalations/${id}`),
    approve: (id: string) => post<{ escalation_id: string; resolution: string; new_tier: number }>(`/escalations/${id}/approve`),
    deny: (id: string) => post<{ escalation_id: string; resolution: string; session_status: string }>(`/escalations/${id}/deny`),
  },

  // Analytics
  analytics: {
    metrics: () => get<Record<string, unknown>>("/analytics/metrics"),
  },
};
