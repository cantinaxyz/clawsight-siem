/**
 * @fileoverview ClawSight SIEM module: platform/src/app/layout.tsx.
 */
import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "@/app/globals.css";
import { requireAdminPageAuth } from "@/lib/server-action-auth";

const geistSans = Geist({
  subsets: ["latin"],
  variable: "--font-geist-sans",
});

const geistMono = Geist_Mono({
  subsets: ["latin"],
  variable: "--font-geist-mono",
});

export const metadata: Metadata = {
  title: "ClawSight SIEM",
  description: "Control plane for OpenClaw telemetry, detections, executions, and policy alerts",
};

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  await requireAdminPageAuth();
  return (
    <html lang="en">
      <body className={`${geistSans.variable} ${geistMono.variable} font-sans antialiased`}>{children}</body>
    </html>
  );
}
