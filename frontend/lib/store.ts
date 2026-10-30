/**
 * lib/store.ts — Zustand global state for Vigil AI dashboard.
 *
 * Stores:
 *  - alertStore: Tier 4 alerts received via WebSocket
 *  - uiStore: sidebar collapse state, active session filter
 */

"use client";

import { create } from "zustand";
import type { Escalation } from "./api";

// ── Alert Store ──────────────────────────────────────────────────────────────

export interface AlertItem {
  id: string;
  session_id: string;
  type: "tier4" | "threat" | "honeytoken";
  message: string;
  timestamp: string;
  read: boolean;
}

interface AlertState {
  alerts: AlertItem[];
  unreadCount: number;
  addAlert: (alert: Omit<AlertItem, "read">) => void;
  markRead: (id: string) => void;
  markAllRead: () => void;
  clearAlerts: () => void;
  // Pending Tier 4 escalations from WS
  pendingEscalations: Escalation[];
  setPendingEscalations: (esc: Escalation[]) => void;
  removeEscalation: (id: string) => void;
}

export const useAlertStore = create<AlertState>((set) => ({
  alerts: [],
  unreadCount: 0,
  pendingEscalations: [],

  addAlert: (alert) =>
    set((state) => {
      const item: AlertItem = { ...alert, read: false };
      return {
        alerts: [item, ...state.alerts].slice(0, 100), // keep last 100
        unreadCount: state.unreadCount + 1,
      };
    }),

  markRead: (id) =>
    set((state) => ({
      alerts: state.alerts.map((a) => (a.id === id ? { ...a, read: true } : a)),
      unreadCount: Math.max(0, state.unreadCount - (state.alerts.find((a) => a.id === id)?.read ? 0 : 1)),
    })),

  markAllRead: () =>
    set((state) => ({
      alerts: state.alerts.map((a) => ({ ...a, read: true })),
      unreadCount: 0,
    })),

  clearAlerts: () => set({ alerts: [], unreadCount: 0 }),

  setPendingEscalations: (esc) => set({ pendingEscalations: esc }),

  removeEscalation: (id) =>
    set((state) => ({
      pendingEscalations: state.pendingEscalations.filter((e) => e.id !== id),
    })),
}));

// ── UI Store ─────────────────────────────────────────────────────────────────

interface UIState {
  sidebarCollapsed: boolean;
  toggleSidebar: () => void;
  activeSessionId: string | null;
  setActiveSessionId: (id: string | null) => void;
}

export const useUIStore = create<UIState>((set) => ({
  sidebarCollapsed: false,
  toggleSidebar: () =>
    set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed })),
  activeSessionId: null,
  setActiveSessionId: (id) => set({ activeSessionId: id }),
}));
