/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/server-action-auth.ts.
 */
import { headers } from "next/headers";
import { authorizeAdminRequest } from "@/lib/auth";

/**
 * Enforces admin bearer-token auth inside Next.js server actions.
 *
 * Server actions do not receive a `Request` object directly, so this helper
 * reconstructs one from the current request headers and reuses the shared
 * admin auth pipeline.
 */
export async function requireAdminServerActionAuth(): Promise<void> {
  const headerList = await headers();
  const req = new Request("http://localhost/_action", {
    headers: headerList,
  });
  const unauthorized = authorizeAdminRequest(req);
  if (unauthorized) {
    throw new Error("Unauthorized");
  }
}
