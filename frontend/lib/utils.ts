/**
 * lib/utils.ts — Vigil AI shared utilities
 */

/** Merge class names, filtering falsy values. */
export function cn(...classes: (string | undefined | null | false)[]): string {
  return classes.filter(Boolean).join(" ");
}

/** Format a timestamp into "X ago" relative string. */
export function timeAgo(date: string | Date): string {
  const d = typeof date === "string" ? new Date(date) : date;
  const diffMs = Date.now() - d.getTime();
  const diffSec = Math.floor(diffMs / 1000);
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  return `${Math.floor(diffHr / 24)}d ago`;
}

/** Truncate a hash string for display (first 8 + last 4). */
export function truncateHash(hash: string): string {
  if (!hash || hash.length < 16) return hash;
  return `${hash.slice(0, 8)}…${hash.slice(-4)}`;
}

/** Return Tailwind class names for a classification label. */
export function classificationClass(cls: string): string {
  switch (cls?.toLowerCase()) {
    case "safe":       return "badge-safe";
    case "suspicious": return "badge-suspicious";
    case "malicious":  return "badge-malicious";
    case "honeytoken": return "badge-honeytoken";
    default:           return "badge-pending";
  }
}

/** Return tier label. */
export function tierLabel(tier: number): string {
  return ["SAFE", "CAUTION", "RESTRICTED", "CRITICAL", "BLACKOUT"][tier] ?? "UNKNOWN";
}

/** Return tier CSS class. */
export function tierClass(tier: number): string {
  return `tier-${Math.min(tier, 4)}`;
}

/** Return tier hex colour (for Recharts). */
export const TIER_COLORS = ["#22C55E", "#FACC15", "#F97316", "#EF4444", "#7C3AED"] as const;

export function tierColor(tier: number): string {
  return TIER_COLORS[Math.min(tier, 4)] ?? "#8B9BB4";
}

/** Format confidence 0-1 to percentage string. */
export function fmtConf(c: number): string {
  return `${Math.round(c * 100)}%`;
}

/** Base API URL from env. */
export const API_URL =
  (typeof window !== "undefined"
    ? (process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000")
    : process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000");
