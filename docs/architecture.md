# ClawSight SIEM Architecture

## Introduction

ClawSight has two connected components:
- The endpoint plugin (`@cantinasecurity/clawsight`), which hooks into OpenClaw runtime lifecycle and emits telemetry.
- The SIEM service, a Next.js + PostgreSQL system that ingests telemetry, enforces remote safety decisions, stores audit evidence, and renders operator workflows.

The SIEM is execution-first: users investigate behavior by execution, then drill down to event/span evidence as needed.

## High-Level ASCII Diagram

```text
                    OpenClaw Runtime (agent)
                              |
                    lifecycle hooks + metadata
                              |
                    ClawSight EDR plugin
          (policy request + telemetry + inventory snapshots)
                 |                           |
                 | guardrail decisions       | telemetry ingest
                 v                           v
          /api/v1/guardrails/decide    /api/telemetry/ingest
                     \                     /
                      \                   /
                       +-----------------+
                       |   SIEM Core     |
                       | normalize/correlate
                       | detect/alert/rollup
                       +-----------------+
                                |
                                v
                         PostgreSQL storage
       (TelemetryEvent, Trace/TraceSpan, ThreatAlert, policy + intent state)
                                |
                                v
                      Next.js UI + SSE streams
  Dashboard | Events | Executions | Alerts | Agents | Safety
```

## High-Level Mermaid Diagram

```mermaid
flowchart LR
    U[User / Trigger Source]
    OC[OpenClaw Runtime]
    PL[ClawSight EDR Plugin]

    GI[/POST /api/v1/guardrails/decide/]
    TI[/POST /api/telemetry/ingest/]

    CORE[SIEM Core\nNormalize + Correlate + Detect + Rollup]
    DB[(PostgreSQL)]
    UI[ClawSight SIEM UI\nDashboard | Events | Executions | Alerts | Agents | Safety]

    U --> OC
    OC --> PL

    PL -->|policy decision requests| GI
    PL -->|telemetry + inventory snapshots| TI

    GI --> CORE
    TI --> CORE

    CORE --> DB
    DB --> UI
```

## Deep Dive

### 1) Technologies and Runtime

- Frontend + API layer: Next.js App Router (server components + API routes).
- Data access: Prisma ORM over PostgreSQL.
- Live updates: SSE endpoints for events/traces streams.
- Endpoint integration: OpenClaw plugin hooks and policy callback contract.

### 2) SIEM Parts

- Ingest pipeline:
  - Accepts batched telemetry (`/api/telemetry/ingest`).
  - Normalizes event shape and metadata.
  - Correlates events into spans/traces/executions.
  - Persists observables and raises alert candidates.
  - DNS enrichment is egress-aware: blocked/error events are skipped and hostname resolution defaults to registrable-domain mode.
- Guardrail API:
  - Receives policy decisions (`/api/v1/guardrails/decide`) for static rules and intent phases.
- Query/API layer:
  - Serves list/detail APIs for dashboard, events, executions, traces, alerts, and agents.
- UI layer:
  - Execution-centric investigation flow.
  - Agent-focused inventory and per-agent safety views.

### 3) How Events Come In, Where They Are Stored, and Where They Are Displayed

1. Plugin intercepts OpenClaw lifecycle hooks (message/session/tool lifecycle).
2. Plugin emits telemetry events to ingest API.
3. SIEM stores normalized rows in telemetry tables, then derives correlation records.
4. SIEM rollups feed:
   - `Dashboard`: 24h activity line chart, event/block/alert pie, top URLs+IPs, top categories, registered agents.
   - `Events`: atomic telemetry event feed and payload drill-down.
   - `Executions`: grouped lifecycle view and execution detail timeline.
   - `Alerts`: aggregated execution-level incidents and investigation workflow.
   - `Agents`: inventory, activity, tool/plugin/skill exposure, per-agent policy.
   - `Safety`: global controls (actions, internet, intent policy).

### 4) Correlation and Execution Model

- Correlation prefers strong execution identifiers (`rootExecutionId`, `traceId`, `rootMessageId`, run/session ids).
- Lifecycle events are normalized into stages (user input, model prep, tool execution, response, completion).
- Execution risk rollups and execution-v2 alert dedupe are keyed by `(projectId, executionId, category)` to preserve tenant isolation in shared-database deployments.
- UI surfaces execution outcome separately from internal warning/error/block counters.

### 5) Auth and Tenancy Boundary

- Capability-separated credentials:
  - `SIEM_INGEST_TOKEN`: plugin-facing ingest/decision routes.
  - `SIEM_ADMIN_TOKEN`: operator control-plane routes (safety + intent config).
- Optional tenant read isolation:
  - `SIEM_PROJECT_TOKENS=projectA:tokenA,projectB:tokenB`
  - server derives allowed `projectId` from token, not from caller query params.
- Enforcement behavior:
  - `401` for missing/invalid token.
  - `403` for valid token + project scope mismatch.
- Compatibility mode:
  - legacy `SIEM_API_TOKEN`/`CLAWSIGHT_API_TOKEN` remains supported, but uses shared privileges and should be avoided in production.
