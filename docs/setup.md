# ClawSight Setup: Plugin + SIEM

## Introduction

ClawSight works as a pair:
- EDR plugin on each OpenClaw agent instance.
- Central ClawSight SIEM receiving telemetry and returning policy decisions.

You can run both locally for development or run the SIEM remotely and connect agents over HTTPS/SSH tunnel.

## High-Level ASCII Diagram

```text
OpenClaw Agent Instance A        OpenClaw Agent Instance B
        |                                  |
   ClawSight plugin                     ClawSight plugin
        |                                  |
        +-------- telemetry + guardrail ----+
                       over HTTP/HTTPS
                              |
                              v
                       ClawSight SIEM
                  (ingest, policy, storage, UI)
```

## Deep Dive

### 1) SIEM Startup

Start the SIEM (database + app). In local environments this is typically done with Docker Compose and then accessed at `http://localhost:3000`.

Security defaults:
- Set a strong `POSTGRES_PASSWORD` in `.env` before running compose.
- Postgres is intentionally not exposed on host ports by default.
- If you need host DB access for local debugging, bind loopback only (`127.0.0.1:5432:5432`) and never publish Postgres publicly.
- DNS enrichment resolves registrable domains by default (`SIEM_DNS_ENRICHMENT_MODE=apex`) to reduce hostname-label data leakage risk.

### 2) Install Plugin and Link to SIEM

Example install command:

```bash
npx -y @cantinasecurity/clawsight install \
  --mode enforce \
  --platform-url http://127.0.0.1:3000 \
  --token devtoken \
  --agent-name openclaw-agent-1 \
  --link
```

Key flags:
- `--platform-url`: SIEM endpoint used for ingest and guardrail calls.
- `--token`: ingest token (`SIEM_INGEST_TOKEN`) used only for plugin-facing endpoints.
- `--mode`: policy mode (`audit` or `enforce` recommended).
- `--agent-name`: stable human-readable identity for agent registry.
- `--link`: links plugin into OpenClaw gateway plugin config.

After install, restart OpenClaw gateway.

### 2.1) Credential Separation (Recommended)

Use separate credentials for least privilege:

```bash
SIEM_INGEST_TOKEN=<plugin-token>
SIEM_ADMIN_TOKEN=<operator-token>
```

- Plugin/OpenClaw should only receive the ingest token.
- SIEM admin UI/API operations should use the admin token.
- App Router UI pages and Server Actions require the admin bearer token on requests (typically enforced by reverse-proxy auth that injects `Authorization` upstream).
- For multi-project read scoping, define tenant tokens:

```bash
SIEM_PROJECT_TOKENS=default:<token-default>,project-a:<token-a>,project-b:<token-b>
```

### 3) Remote SIEM via SSH Tunnel

If SIEM is remote/private, tunnel local port to remote service:

```bash
ssh -N -R 127.0.0.1:3000:127.0.0.1:3000 user@remote-host
```

Then keep plugin `--platform-url` pointed to local forwarded endpoint.

### 4) Verification Flow

After restart:
1. Send a message/task to the agent.
2. Open SIEM `Events` and confirm incoming telemetry.
3. Open `Executions` and confirm execution chain creation.
4. Open `Agents` and confirm inventory (channels/plugins/skills/runtime).

### 5) Multi-Agent Setup

Repeat installation per agent instance with unique `--agent-name` values. This allows per-agent filtering, inventory, and policy overrides in the SIEM.

## Current Limitations

- HTTP can be acceptable for local tunnel setups but production should use HTTPS with proper certs and origin controls.
- Inventory freshness depends on plugin periodic reporting and successful connectivity.
- If plugin was installed without proper agent identity fields, early telemetry may appear as generic/default source until reconfigured.
- Clock skew between agent and server can affect timeline ordering and relative-time UX.
- `TraceOrphan` records are not currently project-attributed, so tenant-scoped tokens cannot access orphan feed endpoints.
