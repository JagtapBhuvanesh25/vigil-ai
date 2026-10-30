/**
 * lib/websocket.ts — WebSocket hook for Vigil AI real-time alerts.
 *
 * Connects to ws://localhost:8000/ws/alerts and dispatches incoming events
 * into the Zustand alert store.
 *
 * Message contract (from backend api/websocket.py):
 *   { type: "tier4" | "threat" | "honeytoken", session_id, message, timestamp }
 */

"use client";

import { useEffect, useRef, useCallback } from "react";
import { useAlertStore } from "./store";

const WS_URL =
  typeof window !== "undefined"
    ? (process.env.NEXT_PUBLIC_WS_URL ?? "ws://localhost:8000/ws/alerts")
    : "ws://localhost:8000/ws/alerts";

export function useVigilWebSocket() {
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const addAlert = useAlertStore((s) => s.addAlert);
  const isMounted = useRef(false);

  const connect = useCallback(() => {
    if (!isMounted.current) return;
    try {
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => {
        console.info("[Vigil WS] connected");
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data as string) as {
            type: "tier4" | "threat" | "honeytoken";
            session_id: string;
            message: string;
            timestamp: string;
          };
          addAlert({
            id: `${data.session_id}-${data.timestamp}-${Math.random()}`,
            session_id: data.session_id,
            type: data.type,
            message: data.message,
            timestamp: data.timestamp,
          });
        } catch {
          console.warn("[Vigil WS] failed to parse message", event.data);
        }
      };

      ws.onerror = () => {
        console.warn("[Vigil WS] connection error — will retry in 5s");
      };

      ws.onclose = () => {
        if (isMounted.current) {
          reconnectTimer.current = setTimeout(connect, 5000);
        }
      };
    } catch (err) {
      console.warn("[Vigil WS] could not connect:", err);
      reconnectTimer.current = setTimeout(connect, 5000);
    }
  }, [addAlert]);

  useEffect(() => {
    isMounted.current = true;
    connect();
    return () => {
      isMounted.current = false;
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
    };
  }, [connect]);
}
