import { redirect } from "next/navigation";

/**
 * Root page — immediately redirects to the dashboard.
 * Phase 1: Redirect only. Full dashboard built in Phase 4.
 */
export default function RootPage() {
  redirect("/dashboard");
}
