/**
 * Dashboard Overview — /dashboard
 * Phase 6: Full implementation with stat cards, charts, and live feeds.
 */

import type { Metadata } from "next";
import { DashboardClient } from "./DashboardClient";

export const metadata: Metadata = {
  title: "Dashboard — Vigil AI",
  description: "Vigil AI containment dashboard — real-time threat monitoring and system health.",
};

export default function DashboardPage() {
  return <DashboardClient />;
}
