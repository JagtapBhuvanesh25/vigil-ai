import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import { ClientProviders } from "./ClientProviders";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-mono",
  subsets: ["latin"],
  display: "swap",
});

export const metadata: Metadata = {
  title: "Vigil AI — Containment-Aware AI Security Platform",
  description:
    "Vigil AI monitors and contains AI agent actions in real-time using a six-layer containment engine. Detect phishing, analyse threats, and enforce runtime security policies.",
  keywords: ["AI security", "containment", "phishing detection", "LLM safety", "prompt injection"],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`${inter.variable} ${jetbrainsMono.variable} h-full antialiased`}
      style={{ colorScheme: "dark" }}
    >
      <body className="h-full flex" style={{ background: "var(--bg-base)", color: "var(--text-primary)" }}>
        <ClientProviders>{children}</ClientProviders>
      </body>
    </html>
  );
}
