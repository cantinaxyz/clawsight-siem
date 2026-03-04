/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/server-action-auth.ts.
 */
import { headers } from "next/headers";
import { notFound } from "next/navigation";
import { authorizeAdminRequest } from "@/lib/auth";

async function isCurrentRequestAdminAuthorized(): Promise<boolean> {
  const headerList = await headers();
  const req = new Request("http://localhost/_auth", {
    headers: headerList,
  });
  return authorizeAdminRequest(req) === null;
}

/**
 * Enforces admin bearer-token auth inside Next.js server actions.
 *
 * Server actions do not receive a `Request` object directly, so this helper
 * reconstructs one from the current request headers and reuses the shared
 * admin auth pipeline.
 */
export async function requireAdminServerActionAuth(): Promise<void> {
  const allowed = await isCurrentRequestAdminAuthorized();
  if (!allowed) {
    throw new Error("Unauthorized");
  }
}

/**
 * Enforces admin bearer-token auth for UI page rendering.
 */
export async function requireAdminPageAuth(): Promise<void> {
  const allowed = await isCurrentRequestAdminAuthorized();
  if (!allowed) {
    notFound();
  }
}
