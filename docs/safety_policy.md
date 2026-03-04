# Safety Policy: Lifecycle Enforcement and Alerts

## Introduction

ClawSight safety policy is enforced through OpenClaw lifecycle hooks. The plugin evaluates deterministic rules and intent policy decisions before risky actions execute, then emits evidence to the SIEM for audit and alerting.

This is how command blocks, domain/IP blocks, and intent drift decisions are applied in real execution flow.

## High-Level ASCII Diagram

```text
message_received
   |
   v
llm_input -----------------> intent_baseline
   |
   v
before_tool_call ----------> static action/domain/IP checks
   |                         + intent_action decision
   |                         + block/warn/allow/modify
   v
tool executes (if allowed)
   |
   v
after_tool_call -----------> intent_output check + sanitization
   |
   v
message_sending -----------> outbound checks
   |
   v
agent_end / llm_output ----> telemetry persisted + execution rollup + alerts
```

## Deep Dive

### 1) OpenClaw Lifecycle Interception

At runtime, plugin hooks key lifecycle points:
- inbound message/session initialization
- model input phase
- pre-tool execution
- post-tool execution
- outbound message phase
- completion markers

This gives both prevention points (pre-action) and evidence points (post-action).

### 1.1) Credential Boundaries

- Runtime/plugin calls (`/api/telemetry/ingest`, `/api/v1/guardrails/decide`) are authenticated with `SIEM_INGEST_TOKEN`.
- Operator configuration and simulation APIs (`/api/safety/*`, `/api/intent/config`) require `SIEM_ADMIN_TOKEN`.
- This separation prevents a compromised ingest credential from directly changing global safety posture.

### 2) Deterministic Safety Controls

Deterministic controls are explicit and predictable:
- command blocking (for example shell patterns and disallowed commands)
- tool allow/deny controls
- internet/domain/IP policies (allow/deny/warn behavior)
- safety action toggles are enforced by generated rules: run-command default mode, download/install controls, and secret-access controls
- the `writeFiles` safety toggle applies to filesystem write tools (`write`, `edit`, `apply_patch`) rather than only direct write calls
- `allowHttpsOnly` is enforced as a static block on insecure `http://` targets across network-capable tools
- domain/IP enforcement resolves mixed matches with strict precedence (`block > warn > allow`) to prevent allowlist-token bypasses from overriding blocked destinations
- domain extraction normalizes IDNs to punycode (IDNA) so Unicode hostnames in scheme-less command strings still participate in domain policy enforcement
- domain/IP extraction also normalizes common IOC obfuscations (`hxxp(s)://`, `[.]`, and `dot` token separators) before policy matching
- prompt-injection `tool_call` hard enforcement in the production guardrail decision path
- command execution guardrails are capability-scoped: `exec` rules also apply to execution-capable tool aliases (`exec`, `bash`, `gateway`)
- for execution command rules, allow-matching is executable-token based (not raw substring), and matching block rules are evaluated before allow rules

These controls provide hard boundaries independent of LLM interpretation.

### 3) Intent Drift Controls

Intent policy complements static controls:
- establishes baseline at execution start.
- checks each action for task alignment.
- inspects output for injection contamination.
- accumulates drift score and can escalate from allow to warn/block.

### 4) Block/Alert Behavior

- A blocked action is denied before tool execution proceeds.
- Plugin emits policy telemetry for every decision.
- SIEM aggregates event-level signals into execution-level alerts for operator triage.
- Execution can still complete even with internal errors; UI distinguishes run outcome from internal policy/error counters.

### 5) What Is Covered

- Command/tool misuse.
- Domain/IP policy violations.
- Task drift and output-injection patterns.
- Execution-level incident rollups for investigations.

## Current Limitations

- Coverage is bounded by available lifecycle hooks and observable tool payloads.
- Actions performed outside instrumented paths are not controllable by this policy layer.
- Domain extraction and normalization can still miss uncommon edge-case URL/text patterns.
- Intent tuning requires calibration to each workload style (strict defaults can over-block exploratory tasks).
