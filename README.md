<p align="center">
  <h1 align="center">ClawSight SIEM</h1>
  <p align="center"><strong>Execution-first security and observability for autonomous AI agents.</strong></p>
  <p align="center"><em>Ingest. Correlate. Enforce. Investigate.</em></p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Next.js-16-black?style=flat-square&logo=nextdotjs" alt="Next.js">
  <img src="https://img.shields.io/badge/PostgreSQL-16-336791?style=flat-square&logo=postgresql" alt="PostgreSQL">
  <img src="https://img.shields.io/badge/Prisma-ORM-2D3748?style=flat-square&logo=prisma" alt="Prisma">
  <img src="https://img.shields.io/badge/runtime-Node.js-5FA04E?style=flat-square&logo=nodedotjs" alt="Node.js">
  <img src="https://img.shields.io/badge/Docker-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/Docker_Compose-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Docker Compose">
</p>

---

<p align="center">
  <a href="#quick-start">Quick start</a> &middot;
  <a href="#required-configuration">Configuration</a> &middot;
  <a href="#openclaw-plugin-wiring">Plugin wiring</a> &middot;
  <a href="#product-surfaces">Product surfaces</a> &middot;
  <a href="#intent-based-policy-architecture">Intent policy</a> &middot;
  <a href="#api-overview">API</a>
</p>

<p align="center">
  <a href="docs/overview.md">SIEM Overview</a> &middot;
  <a href="docs/architecture.md">Architecture</a> &middot;
  <a href="docs/setup.md">Setup</a> &middot;
  <a href="docs/safety_policy.md">Safety Policy</a> &middot;
  <a href="docs/intent_drift.md">Intent Drift</a>
</p>

---

## What is ClawSight SIEM?

ClawSight SIEM is the control plane for ClawSight EDR agents running on OpenClaw instances. It ingests lifecycle telemetry, correlates activity into executions, applies guardrail decisions, and gives operators a unified interface to investigate behavior and enforce policy.

Core capabilities:
- Ingest normalized telemetry from OpenClaw-integrated plugins.
- Correlate events into execution chains (`Trace` + `TraceSpan` compatibility model).
- Persist unmatched telemetry separately (`TraceOrphan`) for audit integrity.
- Preserve payload evidence (`payload` and `payloadRedacted`) for investigation.
- Power live operator views across Dashboard, Events, Executions, Alerts, Agents, and Safety.

## Architecture diagram

```mermaid
flowchart LR
    subgraph RUNTIME[OpenClaw Runtime]
        U[User or Trigger]
        CH[Channel and Automation Sources<br/>Telegram, Discord, Webchat, Cron, Webhook]
        OC[OpenClaw Session Lifecycle]
        PL[ClawSight Plugin Hooks<br/>message, llm_input, before_tool_call, after_tool_call]
        U --> CH --> OC --> PL
    end

    subgraph SIEM[ClawSight SIEM]
        ING[Ingest API<br/>POST /api/telemetry/ingest]
        DEC[Decision API<br/>POST /api/v1/guardrails/decide]
        NORM[Normalization and Enrichment<br/>schema validation, source metadata, observables]
        CORR[Correlation Pipeline<br/>events to spans to traces to executions]
        POL[Policy Evaluation<br/>static safety rules plus intent drift]
        DET[Detection and Alert Aggregation<br/>execution-level incidents]
        DB[(PostgreSQL<br/>TelemetryEvent, TraceSpan, Trace,<br/>ExecutionIntent, IntentDecision,<br/>ThreatAlert, ManagedAgent)]
        QUERY[Query APIs<br/>/events, /executions, /alerts, /agents, /safety]
        SSE[Live Streams<br/>/api/telemetry/events/stream,<br/>/api/traces/stream]

        ING --> NORM --> CORR
        DEC --> POL --> CORR
        CORR --> DET
        CORR --> DB
        POL --> DB
        DET --> DB
        DB --> QUERY
        DB --> SSE
    end

    subgraph UI[Operator Experience]
        DASH[Dashboard]
        EV[Events]
        EX[Executions]
        AL[Alerts]
        AG[Agents]
        SA[Safety]
    end

    PL -->|telemetry envelopes and inventory| ING
    PL -->|policy and intent checks| DEC

    QUERY --> DASH
    QUERY --> EV
    QUERY --> EX
    QUERY --> AL
    QUERY --> AG
    QUERY --> SA
    SSE --> EV
    SSE --> EX
```


## Quick start (Docker Compose)

```bash
cp .env.example .env
echo 'SIEM_API_TOKEN=devtoken' >> .env
docker compose up --build
```

Default local URL: `http://127.0.0.1:3000`

## Local development (pnpm)

```bash
cd platform
cp .env.example .env
pnpm install
pnpm exec prisma migrate dev
pnpm dev
```

## Required configuration

Set ingest token (recommended outside local-only testing):

```bash
echo 'siem_API_TOKEN=devtoken' >> .env
```

For intent-policy LLM extraction/alignment checks (and optional inbound prompt-injection classification):

```bash
echo 'OPENAI_API_KEY=sk-...' >> .env
```

## OpenClaw plugin wiring

```bash
npx -y @cantinasecurity/clawsight install \
  --mode enforce \
  --platform-url http://127.0.0.1:3000 \
  --token devtoken \
  --agent-name openclaw-lab-prod \
  --link
```

At startup, plugin emits `agent.bootstrap` and `agent.inventory_snapshot` with:
- stable `agentInstanceId` (persisted locally by plugin)
- mutable `agentName`
- host / OS / runtime metadata
- channels, plugins, and skills inventory snapshot

SIEM upserts `ManagedAgent` from these events.

## Docs

- [`docs/overview.md`](docs/overview.md): page-by-page product behavior and investigation workflow.
- [`docs/architecture.md`](docs/architecture.md): SIEM architecture, ingest/correlation/storage, and system boundaries.
- [`docs/setup.md`](docs/setup.md): plugin + SIEM setup patterns and deployment examples.
- [`docs/safety_policy.md`](docs/safety_policy.md): lifecycle enforcement model for static and intent controls.
- [`docs/intent_drift.md`](docs/intent_drift.md): intent drift model, scoring approach, and current limitations.
- [`docs/api.md`](docs/api.md): all API endpoints with one-line descriptions.
