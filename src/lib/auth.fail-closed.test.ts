import { afterEach, describe, expect, it, vi } from "vitest";

const AUTH_ENV_KEYS = [
  "siem_API_TOKEN",
  "SIEM_API_TOKEN",
  "CLAWSIGHT_API_TOKEN",
  "SIEM_INGEST_TOKEN",
  "CLAWSIGHT_INGEST_TOKEN",
  "SIEM_ADMIN_TOKEN",
  "CLAWSIGHT_ADMIN_TOKEN",
  "SIEM_PROJECT_TOKENS",
  "CLAWSIGHT_PROJECT_TOKENS",
] as const;

const ORIGINAL_ENV = new Map<string, string | undefined>(
  AUTH_ENV_KEYS.map((key) => [key, process.env[key]]),
);

function setAuthEnv(values: Partial<Record<(typeof AUTH_ENV_KEYS)[number], string>>) {
  for (const key of AUTH_ENV_KEYS) {
    delete process.env[key];
  }
  for (const [key, value] of Object.entries(values)) {
    process.env[key] = value;
  }
}

async function loadAuthModule() {
  vi.resetModules();
  return import("@/lib/auth");
}

describe("auth helpers fail closed when tokens are unset", () => {
  afterEach(() => {
    for (const key of AUTH_ENV_KEYS) {
      const original = ORIGINAL_ENV.get(key);
      if (typeof original === "string") {
        process.env[key] = original;
      } else {
        delete process.env[key];
      }
    }
    vi.resetModules();
  });

  it("rejects admin/ingest/read requests when no auth tokens are configured", async () => {
    setAuthEnv({});
    const {
      authorizeRequest,
      authorizeAdminRequest,
      authorizeIngestRequest,
      authorizeReadRequest,
    } = await loadAuthModule();

    const req = new Request("http://localhost/api/check");
    expect(authorizeRequest(req)?.status).toBe(401);
    expect(authorizeAdminRequest(req)?.status).toBe(401);
    expect(authorizeIngestRequest(req)?.status).toBe(401);
    expect(authorizeReadRequest(req)?.status).toBe(401);
  });

  it("authorizes only when a matching token is provided", async () => {
    setAuthEnv({
      SIEM_ADMIN_TOKEN: "admin-token",
      SIEM_INGEST_TOKEN: "ingest-token",
      SIEM_API_TOKEN: "read-token",
    });
    const {
      authorizeRequest,
      authorizeAdminRequest,
      authorizeIngestRequest,
      authorizeReadRequest,
    } = await loadAuthModule();

    const adminReq = new Request("http://localhost/api/check", {
      headers: { authorization: "Bearer admin-token" },
    });
    const ingestReq = new Request("http://localhost/api/check", {
      headers: { authorization: "Bearer ingest-token" },
    });
    const readReq = new Request("http://localhost/api/check", {
      headers: { authorization: "Bearer read-token" },
    });
    const badReq = new Request("http://localhost/api/check", {
      headers: { authorization: "Bearer wrong-token" },
    });

    expect(authorizeRequest(adminReq)).toBeNull();
    expect(authorizeAdminRequest(adminReq)).toBeNull();
    expect(authorizeIngestRequest(ingestReq)).toBeNull();
    expect(authorizeReadRequest(readReq)).toBeNull();
    expect(authorizeAdminRequest(badReq)?.status).toBe(401);
    expect(authorizeIngestRequest(badReq)?.status).toBe(401);
    expect(authorizeReadRequest(badReq)?.status).toBe(401);
  });
});
