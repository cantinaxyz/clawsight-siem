/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/auth.ts.
 */
const siemToken =
  process.env.siem_API_TOKEN?.trim() ||
  process.env.SIEM_API_TOKEN?.trim() ||
  process.env.CLAWSIGHT_API_TOKEN?.trim() ||
  "";

function extractBearer(req: Request): string {
  const raw = req.headers.get("authorization")?.trim() ?? "";
  if (!raw.toLowerCase().startsWith("bearer ")) {
    return raw.trim();
  }
  return raw.slice(7).trim();
}

/**
 * Validates bearer token auth for protected API routes.
 *
 * @returns `null` when authorized, otherwise a 401 `Response` object.
 */
export function authorizeRequest(req: Request): Response | null {
  if (!siemToken) {
    return null;
  }
  const provided = extractBearer(req);
  if (!provided || provided !== siemToken) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }
  return null;
}
