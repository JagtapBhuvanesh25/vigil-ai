"use client";

import { Toaster } from "sonner";
import { Sidebar } from "@/components/layout/Sidebar";
import { Topbar } from "@/components/layout/Topbar";
import { useVigilWebSocket } from "@/lib/websocket";
import { useAlertStore } from "@/lib/store";
import { Tier4Modal } from "@/components/shared/Tier4Modal";
import { useState } from "react";
import type { Escalation } from "@/lib/api";

function WebSocketInit() {
  useVigilWebSocket();
  return null;
}

export function ClientProviders({ children }: { children: React.ReactNode }) {
  const pendingEscalations = useAlertStore((s) => s.pendingEscalations);
  const [activeModal, setActiveModal] = useState<Escalation | null>(null);

  // Show modal for first pending escalation automatically
  const firstPending = pendingEscalations[0];

  return (
    <>
      <WebSocketInit />
      <Sidebar />
      <div className="flex flex-col flex-1 min-h-screen overflow-hidden">
        <Topbar />
        <main className="flex-1 overflow-y-auto scrollbar-thin">
          {children}
        </main>
      </div>
      {/* Tier 4 modal — auto-shows for pending escalations */}
      {(activeModal ?? firstPending) && (
        <Tier4Modal
          escalation={activeModal ?? firstPending}
          onClose={() => setActiveModal(null)}
          onResolved={() => setActiveModal(null)}
        />
      )}
      <Toaster
        position="bottom-right"
        theme="dark"
        toastOptions={{
          style: {
            background: "var(--bg-elevated)",
            border: "1px solid var(--border-subtle)",
            color: "var(--text-primary)",
          },
        }}
      />
    </>
  );
}
