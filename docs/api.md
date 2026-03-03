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

## Telemetry Ingest and Stream

- `POST /api/telemetry/ingest`  
  Ingests telemetry event batches from plugin/runtime sources.
- `POST /v1/telemetry/ingest`  
  Alias route for telemetry ingest compatibility.
- `GET /api/telemetry/events`  
  Returns normalized telemetry events with filters and pagination controls.
- `GET /api/telemetry/events/stream`  
  Streams live telemetry events over SSE for real-time UI updates.

## Guardrails and Decisions

- `POST /api/v1/guardrails/decide`  
  Evaluates policy/intent decisions for tool/message/baseline/action/output checks.
- `POST /v1/guardrails/decide`  
  Alias route for guardrail decision compatibility.
- `POST /api/v1/payments/send`  
  Disabled payments endpoint that intentionally returns `410 Gone`.
- `POST /v1/payments/send`  
  Alias route for the disabled payments endpoint.

## Executions

- `GET /api/executions`  
  Lists execution rollups with trigger/outcome/timing/tool metrics.
- `GET /api/executions/:executionId/lineage`  
  Returns detailed execution lineage and grouped timeline data.

## Traces (Compatibility and Low-Level Debug)

- `GET /api/traces`  
  Lists trace-level correlation records with filters.
- `GET /api/traces/stats`  
  Returns aggregate trace statistics for a selected time window.
- `GET /api/traces/stream`  
  Streams trace updates over SSE.
- `GET /api/traces/:traceId`  
  Returns one trace with summary metadata.
- `GET /api/traces/:traceId/spans`  
  Returns spans for a trace with cursor-based pagination.
- `GET /api/traces/orphans`  
  Lists orphan telemetry records that could not be safely correlated.

## Alerts

- `GET /api/security/alerts`  
  Returns alert records for triage and investigations.
- `POST /api/admin/alerts/migrate-v2`  
  Admin utility endpoint to migrate/normalize alert records into execution-v2 model.

## Agents

- `GET /api/agents`  
  Lists managed agents with filters and summary metadata.
- `GET /api/agents/:agentKey`  
  Returns one managed agent profile.
- `PATCH /api/agents/:agentKey`  
  Updates mutable agent fields (for example display/profile metadata).
- `DELETE /api/agents/:agentKey`  
  Deletes a managed agent record and related references as implemented by backend logic.
- `POST /api/agents/:agentKey/profile`  
  Saves agent profile data and scoped policy fields via API form payload.

## Safety and Intent Configuration

- `GET /api/safety/config`  
  Returns current global static safety configuration.
- `POST /api/safety/config`  
  Updates global static safety configuration.
- `POST /api/safety/simulate`  
  Runs static safety policy simulation against provided request payload.
- `GET /api/safety/intent-policy`  
  Returns global intent policy configuration and defaults.
- `POST /api/safety/intent-policy`  
  Saves global intent policy configuration.
- `GET /api/safety/intent-policy/impact`  
  Returns intent-policy impact metrics (for example last-24h evaluations/blocks/warns).
- `POST /api/safety/intent-policy/simulate`  
  Runs intent policy simulation for baseline/action/output testing.

## Intent Operational APIs

- `GET /api/intent/config`  
  Returns effective intent configuration for UI/runtime consumers.
- `POST /api/intent/config`  
  Saves intent configuration payload.
- `GET /api/intent/executions/by-root/:rootExecutionId`  
  Returns intent baseline and decisions for a root execution id.
- `PATCH /api/intent/executions/by-root/:rootExecutionId`  
  Applies intent baseline patch/update operations for that execution.


