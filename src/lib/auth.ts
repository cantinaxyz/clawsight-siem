/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/auth.ts.
 */
import { Prisma } from "@prisma/client";

const siemToken =
  process.env.siem_API_TOKEN?.trim() ||
  process.env.SIEM_API_TOKEN?.trim() ||
  process.env.CLAWSIGHT_API_TOKEN?.trim() ||
  "";

const ingestToken =
  process.env.SIEM_INGEST_TOKEN?.trim() ||
  process.env.CLAWSIGHT_INGEST_TOKEN?.trim() ||
  siemToken;

const adminToken =
  process.env.SIEM_ADMIN_TOKEN?.trim() ||
  process.env.CLAWSIGHT_ADMIN_TOKEN?.trim() ||
  siemToken;

type AuthContext =
  | { kind: "none" }
  | { kind: "global" }
  | { kind: "project"; projectId: string };

const projectTokenSpec =
  process.env.SIEM_PROJECT_TOKENS?.trim() ||
  process.env.CLAWSIGHT_PROJECT_TOKENS?.trim() ||
  "";

const projectTokenEntries = parseProjectTokens(projectTokenSpec);
const hasProjectScopedAuth = projectTokenEntries.length > 0;

const tokenToProject = new Map<string, string>(
  projectTokenEntries.map((entry) => [entry.token, entry.projectId]),
);

function parseProjectTokens(raw: string): Array<{ projectId: string; token: string }> {
  if (!raw) return [];
  const entries: Array<{ projectId: string; token: string }> = [];
  for (const pair of raw.split(/[,\n;]+/)) {
    const trimmed = pair.trim();
    if (!trimmed) continue;
    const sep = trimmed.indexOf(":");
    if (sep <= 0) continue;
    const projectId = normalizeProjectId(trimmed.slice(0, sep));
    const token = trimmed.slice(sep + 1).trim();
    if (!projectId || !token) continue;
    entries.push({ projectId, token });
  }
  return entries;
}

function normalizeProjectId(value: string | null | undefined): string {
  const normalized = String(value ?? "").trim().toLowerCase();
  return normalized || "default";
}

function extractBearer(req: Request): string {
  const raw = req.headers.get("authorization")?.trim() ?? "";
  if (!raw.toLowerCase().startsWith("bearer ")) {
    return raw.trim();
  }
  return raw.slice(7).trim();
}

function resolveAuthContext(
  req: Request,
  options?: { requireToken?: boolean; capability?: "scope" | "admin" | "ingest" },
): {
  context?: AuthContext;
  response?: Response;
} {
  const requireToken = options?.requireToken === true;
  const capability = options?.capability || "scope";
  const provided = extractBearer(req);

  const expectedStaticToken =
    capability === "admin"
      ? adminToken
      : capability === "ingest"
        ? ingestToken
        : siemToken;

  if (!hasProjectScopedAuth) {
    if (!expectedStaticToken) {
      return { context: { kind: "none" } };
    }
    if (!provided) {
      if (requireToken) {
        return { response: Response.json({ error: "Unauthorized" }, { status: 401 }) };
      }
      return { context: { kind: "none" } };
    }
    if (provided !== expectedStaticToken) {
      return { response: Response.json({ error: "Unauthorized" }, { status: 401 }) };
    }
    return { context: { kind: "global" } };
  }

  if (!provided) {
    return { response: Response.json({ error: "Unauthorized" }, { status: 401 }) };
  }

  if (capability === "admin") {
    if (!adminToken || provided !== adminToken) {
      return { response: Response.json({ error: "Unauthorized" }, { status: 401 }) };
    }
    return { context: { kind: "global" } };
  }

  if (capability === "ingest") {
    if (!ingestToken || provided !== ingestToken) {
      return { response: Response.json({ error: "Unauthorized" }, { status: 401 }) };
    }
    return { context: { kind: "global" } };
  }

  if ((adminToken && provided === adminToken) || (siemToken && provided === siemToken)) {
    return { context: { kind: "global" } };
  }

  const projectId = tokenToProject.get(provided);
  if (!projectId) {
    return { response: Response.json({ error: "Unauthorized" }, { status: 401 }) };
  }
  return { context: { kind: "project", projectId } };
}

/**
 * Validates bearer token auth for protected API routes.
 *
 * @returns `null` when authorized, otherwise a 401 `Response` object.
 */
export function authorizeRequest(req: Request): Response | null {
  const auth = resolveAuthContext(req, { requireToken: true, capability: "admin" });
  if (auth.response) {
    return auth.response;
  }
  return null;
}

/**
 * Validates bearer token auth for ingest/agent-facing API routes.
 */
export function authorizeIngestRequest(req: Request): Response | null {
  const auth = resolveAuthContext(req, { requireToken: true, capability: "ingest" });
  if (auth.response) {
    return auth.response;
  }
  return null;
}

/**
 * Validates bearer token auth for operator/admin API routes.
 */
export function authorizeAdminRequest(req: Request): Response | null {
  const auth = resolveAuthContext(req, { requireToken: true, capability: "admin" });
  if (auth.response) {
    return auth.response;
  }
  return null;
}

/**
 * Resolves caller project scope from auth context and optional query input.
 *
 * In project-token mode, scope is always forced to the token-bound project and
 * conflicting caller-supplied `projectId` values are rejected.
 */
export function resolveProjectScope(
  req: Request,
  requestedProjectId?: string | null,
): { projectId?: string; response?: Response } {
  const auth = resolveAuthContext(req, { requireToken: false, capability: "scope" });
  if (auth.response) {
    return { response: auth.response };
  }

  const requested = requestedProjectId?.trim() || undefined;
  const requestedNormalized = requested ? normalizeProjectId(requested) : undefined;
  const context = auth.context ?? { kind: "none" as const };

  if (context.kind !== "project") {
    return { projectId: requestedNormalized };
  }

  if (requestedNormalized && requestedNormalized !== context.projectId) {
    return {
      response: Response.json(
        { error: "Forbidden: project scope mismatch" },
        { status: 403 },
      ),
    };
  }
  return { projectId: context.projectId };
}

/**
 * Builds a Prisma filter input for normalized project scope.
 */
export function buildProjectWhere(projectId: string): Prisma.TelemetryEventWhereInput {
  if (projectId === "default") {
    return {
      OR: [{ projectId: null }, { projectId: "" }, { projectId: "default" }],
    };
  }
  return { projectId };
}

/**
 * Builds a SQL predicate for normalized project scope.
 */
export function buildProjectSqlCondition(column: Prisma.Sql, projectId: string): Prisma.Sql {
  if (projectId === "default") {
    return Prisma.sql`COALESCE(NULLIF(${column}, ''), 'default') = 'default'`;
  }
  return Prisma.sql`COALESCE(NULLIF(${column}, ''), 'default') = ${projectId}`;
}
