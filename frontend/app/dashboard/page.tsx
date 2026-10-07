/**
 * Vigil AI Dashboard — Phase 1 Placeholder
 *
 * This page is a structural placeholder. The full dashboard UI
 * (risk gauge, email queue, audit timeline, threat map) is built in Phase 4.
 */

import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Dashboard — Vigil AI",
  description: "Vigil AI containment dashboard — real-time threat monitoring.",
};

export default function DashboardPage() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center bg-gray-950 px-6">
      {/* ── Logo mark ───────────────────────────────────────────────────────── */}
      <div className="mb-8 flex items-center gap-3">
        <div
          className="flex h-12 w-12 items-center justify-center rounded-xl"
          style={{ background: "linear-gradient(135deg, #6366f1, #8b5cf6)" }}
          aria-hidden="true"
        >
          <svg
            width="24"
            height="24"
            viewBox="0 0 24 24"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V7L12 2z"
              fill="white"
              fillOpacity="0.9"
            />
          </svg>
        </div>
        <span
          className="text-2xl font-bold tracking-tight text-white"
          style={{ fontFamily: "var(--font-inter)" }}
        >
          Vigil AI
        </span>
      </div>

      {/* ── Status card ──────────────────────────────────────────────────────── */}
      <div
        className="w-full max-w-md rounded-2xl border border-gray-800 p-8 text-center"
        style={{ background: "rgba(17,24,39,0.8)", backdropFilter: "blur(12px)" }}
      >
        <div className="mb-4 flex items-center justify-center gap-2">
          <span className="inline-block h-2.5 w-2.5 animate-pulse rounded-full bg-emerald-400" />
          <span className="text-sm font-medium text-emerald-400">
            System Initializing
          </span>
        </div>

        <h1 className="mb-2 text-xl font-semibold text-white">
          Containment Engine Ready
        </h1>
        <p className="mb-6 text-sm leading-relaxed text-gray-400">
          Phase 1 foundation is live. The six-layer containment core, database
          schema, and API are bootstrapped. The full dashboard UI will be built
          in Phase 4.
        </p>

        {/* Phase progress */}
        <div className="space-y-2 text-left">
          {[
            { label: "Phase 1 — Foundation & Setup", done: true },
            { label: "Phase 2 — Containment Engine", done: false },
            { label: "Phase 3 — Email Intelligence Agent", done: false },
            { label: "Phase 4 — Dashboard UI", done: false },
            { label: "Phase 5 — Safe Browsing Shield", done: false },
            { label: "Phase 6 — Production Hardening", done: false },
          ].map((phase) => (
            <div key={phase.label} className="flex items-center gap-3">
              <span
                className={`flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-xs font-bold ${
                  phase.done
                    ? "bg-emerald-500 text-white"
                    : "border border-gray-700 text-gray-600"
                }`}
              >
                {phase.done ? "✓" : "○"}
              </span>
              <span
                className={`text-sm ${phase.done ? "text-emerald-300" : "text-gray-500"}`}
              >
                {phase.label}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* ── API health link ──────────────────────────────────────────────────── */}
      <p className="mt-6 text-xs text-gray-600">
        Backend API:{" "}
        <a
          id="health-link"
          href={`${process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000"}/health`}
          target="_blank"
          rel="noopener noreferrer"
          className="text-indigo-400 hover:text-indigo-300 underline transition-colors"
        >
          {process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000"}/health
        </a>
      </p>
    </main>
  );
}
