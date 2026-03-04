# ClawSight SIEM API Reference

## Introduction

This document lists every current API endpoint in the ClawSight SIEM app, with method, route, and a one-line purpose.

## High-Level ASCII Diagram

```text
Plugin / Client
   |
   +--> Ingest APIs (/api/telemetry/ingest, /v1/telemetry/ingest)
   |
   +--> Guardrail APIs (/api/v1/guardrails/decide, /v1/guardrails/decide)
   |
   +--> Query APIs (/api/events, /api/executions, /api/agents, /api/traces, ...)
   |
   +--> Safety/Intent Admin APIs
```

## Deep Dive

## Auth and Scope Model

- Ingest-facing endpoints use `SIEM_INGEST_TOKEN`.
- Operator/control endpoints use `SIEM_ADMIN_TOKEN`.
- Read/query endpoints require bearer auth (`SIEM_ADMIN_TOKEN`, legacy shared token, or tenant token) and enforce server-side project scope when `SIEM_PROJECT_TOKENS` is configured.
- Legacy `SIEM_API_TOKEN` / `CLAWSIGHT_API_TOKEN` still work as compatibility fallback if split tokens are not set.
- Read responses return redacted payload content only; raw telemetry payloads are kept server-side for internal persistence.
- Error semantics:
  - `401 Unauthorized`: missing or invalid token for required surface.
  - `403 Forbidden`: token is valid but requested `projectId` does not match token-bound scope.

## Telemetry Ingest and Stream

- `POST /api/telemetry/ingest`  
  Ingests telemetry event batches from plugin/runtime sources. Auth: ingest token.
- `POST /v1/telemetry/ingest`  
  Alias route for telemetry ingest compatibility. Auth: ingest token.
- `GET /api/telemetry/events`  
  Returns normalized telemetry events with filters and pagination controls. Auth: required read token (project scope enforced in tenant-token mode).
- `GET /api/telemetry/events/stream`  
  Streams live telemetry events over SSE for real-time UI updates. Auth: required read token (project scope enforced in tenant-token mode).

## Guardrails and Decisions

- `POST /api/v1/guardrails/decide`  
  Evaluates policy/intent decisions for tool/message/baseline/action/output checks; `kind=tool` composes static policy + prompt-injection `tool_call` hard enforcement (prompt block overrides static allow/warn/modify). Auth: ingest token.
- `POST /v1/guardrails/decide`  
  Alias route for guardrail decision compatibility. Auth: ingest token.
- `POST /api/v1/payments/send`  
  Disabled payments endpoint that intentionally returns `410 Gone`. Auth: ingest token.
- `POST /v1/payments/send`  
  Alias route for the disabled payments endpoint. Auth: ingest token.

## Executions

- `GET /api/executions`  
  Lists execution rollups with trigger/outcome/timing/tool metrics. Auth: required read token (project scope enforced in tenant-token mode).
- `GET /api/executions/:executionId/lineage`  
  Returns detailed execution lineage and grouped timeline data. Auth: required read token (project scope enforced in tenant-token mode).

## Traces (Compatibility and Low-Level Debug)

- `GET /api/traces`  
  Lists trace-level correlation records with filters. Auth: required read token (project scope enforced in tenant-token mode).
- `GET /api/traces/stats`  
  Returns aggregate trace statistics for a selected time window. Auth: required read token (project scope enforced in tenant-token mode).
- `GET /api/traces/stream`  
  Streams trace updates over SSE. Auth: required read token (project scope enforced in tenant-token mode).
- `GET /api/traces/:traceId`  
  Returns one trace with summary metadata. Auth: required read token (project scope enforced in tenant-token mode).
- `GET /api/traces/:traceId/spans`  
  Returns spans for a trace with cursor-based pagination. Auth: required read token (project scope enforced in tenant-token mode).
- `GET /api/traces/orphans`  
  Lists orphan telemetry records that could not be safely correlated. Auth: admin/global only; tenant-scoped tokens receive `403`.

## Alerts

- `GET /api/security/alerts`  
  Returns alert records for triage and investigations. Auth: required (admin token, legacy shared token, or tenant token), with server-side project-scope enforcement when tenant tokens are enabled.
- `POST /api/admin/alerts/migrate-v2`  
  Admin utility endpoint to migrate/normalize alert records into execution-v2 model. Auth: admin token.

## Agents

- `GET /api/agents`  
  Lists managed agents with filters and summary metadata. By default returns a sanitized projection (excludes `runtimeMeta` and `notes`). Set `includeSensitive=1` to return full records; this requires admin token. Auth: required read token (project scope enforced in tenant-token mode).
- `GET /api/agents/:agentKey`  
  Returns one managed agent profile. Auth: required read token (project scope enforced in tenant-token mode).
- `PATCH /api/agents/:agentKey`  
  Updates mutable agent fields (for example display/profile metadata). Auth: admin token.
- `DELETE /api/agents/:agentKey`  
  Deletes a managed agent record and related references using key-authoritative identity scope; alert/risk cleanup is project-scoped and orphan cleanup is restricted to key-bound session scope. Auth: admin token.
- `POST /api/agents/:agentKey/profile`  
  Saves agent profile data and scoped policy fields via API form payload. Auth: admin token.

## Safety and Intent Configuration

- `GET /api/safety/config`  
  Returns current global static safety configuration. Auth: admin token.
- `POST /api/safety/config`  
  Updates global static safety configuration. Auth: admin token.
- `POST /api/safety/simulate`  
  Runs static safety policy simulation against provided request payload. Auth: admin token.
- `GET /api/safety/intent-policy`  
  Returns global intent policy configuration and defaults. Auth: admin token.
- `POST /api/safety/intent-policy`  
  Saves global intent policy configuration. Auth: admin token.
- `GET /api/safety/intent-policy/impact`  
  Returns intent-policy impact metrics (for example last-24h evaluations/blocks/warns). Auth: admin token.
- `POST /api/safety/intent-policy/simulate`  
  Runs intent policy simulation for baseline/action/output testing. Auth: admin token.

## Intent Operational APIs

- `GET /api/intent/config`  
  Returns effective intent configuration for UI/runtime consumers. Auth: admin token.
- `POST /api/intent/config`  
  Saves intent configuration payload. Auth: admin token.
- `GET /api/intent/executions/by-root/:rootExecutionId`  
  Returns intent baseline and decisions for a root execution id. Auth: required read token (project scope enforced in tenant-token mode).
- `PATCH /api/intent/executions/by-root/:rootExecutionId`  
  Applies intent baseline patch/update operations for that execution. Auth: admin token.
