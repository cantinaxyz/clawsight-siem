# ClawSight UI Overview

## Introduction

This document explains each primary page in ClawSight SIEM and how operators should use them together: dashboard, events, executions, alerts, agents, and safety.

ClawSight is execution-centric: events are raw evidence, executions are behavior narratives, alerts are incident rollups.

## High-Level ASCII Diagram

```text
Dashboard (24h posture)
      |
      +--> Events (atomic telemetry search + payload evidence)
      |
      +--> Executions (grouped lifecycle + investigation timeline)
      |         |
      |         +--> Execution detail (intent + raw)
      |
      +--> Alerts (execution-level incidents + triage workflow)
      |
      +--> Agents (inventory/activity/policy per agent)
      |
      +--> Safety (global actions/internet/intent policy)
```

## Deep Dive

### 1) Dashboard

Purpose:
- Quick operational posture for last 24h.

Main sections:
- Total activity line chart.
- Activity pie (events, blocks, alerts).
- Top called URLs mapped to resolved IPs.
- Top telemetry categories.
- Registered agent count in page subtitle.

### 2) Events Page

Purpose:
- Raw telemetry feed across all agents and executions.

What it shows:
- event time, category/action, severity/outcome, source context, execution linkage.
- expandable row details with parsed summary + raw payload.
- live stream mode through SSE for near-real-time updates.

Best use:
- low-level debugging and evidence verification.

### 3) Executions Page

Purpose:
- Primary behavior investigation surface.

What it shows:
- execution list with trigger, outcome, duration, and tool counts.
- expandable row summary.
- full execution detail page for grouped lifecycle timeline.

Execution details:
- grouped phases (input, prep, execution, response, completion).
- intent view (baseline + decision/drift progression).
- raw mode for full JSON evidence.

### 4) Alerts Page

Purpose:
- Incident triage and investigation.

When alerts are raised:
- policy and intent signals are aggregated to execution-level incidents.
- the page prioritizes severity/status and links to the relevant execution context.

How to use:
- filter to open alerts.
- acknowledge/unacknowledge/resolve.
- inspect timeline and policy decision evidence.
- move to execution/events for deeper forensic context.

### 5) Agents Page

Purpose:
- Asset inventory and per-agent operations.

Agent list:
- card view with identity, health/activity counters, runtime/access metadata.

Agent detail:
- `Overview`: inventory, domains, recent execution activity.
- `Activity`: execution history for that agent.
- `Tools`: skill/tool/plugin view.
- `Policy`: agent-scoped policy controls and intent override handling.
- `Settings`: metadata edits and delete action.

### 6) Safety Page

Purpose:
- Global policy management.

Tabs:
- `Actions`: command/tool-level deterministic restrictions, including a default run-commands mode and allow/warn/block command lists.
- `Internet`: network/domain policy controls.
- `Intent policy`: drift model mode, thresholds, tuning, and advanced behavior.

Scope model:
- Global safety is configured here.
- Agent-specific custom policy is configured from each agent’s policy tab.
