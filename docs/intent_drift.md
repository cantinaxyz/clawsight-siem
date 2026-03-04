# Intent Drift: Model and Enforcement

## Introduction

Intent drift is the gap between what the user asked and what the agent is doing during an execution. Static blocklists alone cannot cover this space for autonomous agents. ClawSight addresses drift with execution-aware policy checks that operate at baseline extraction, action time, and output time.

## High-Level ASCII Diagram

```text
User task
  |
  v
intent_baseline (once per execution)
  -> expected boundary + scopes + domains
  |
  +--> intent_action (each tool.before_tool_call)
  |      compare action against baseline
  |      update drift score
  |      decision: allow | warn | block | modify
  |
  +--> intent_output (each tool.after_tool_call)
         scan output for instruction injection
         optional sanitization
         update drift score
```

## Deep Dive

### 1) Why Static Rules Are Not Enough

1. Novel malicious domains/skills/commands appear faster than static lists can track.
2. The important question is often not “is this command always bad,” but “is this action aligned to this task now.”
3. Indirect prompt injection can be carried through tool output and only becomes visible in subsequent action choices.

### 2) Three Intent Phases in ClawSight

1. `intent_baseline`:
   - Triggered at first `llm_input`.
   - Produces expected scopes/domains and a task boundary summary.
   - Uses system prompt + current user task only for boundary expansion; recent history/tool output context is excluded to reduce baseline poisoning risk.
2. `intent_action`:
   - Triggered before each tool call.
   - Scores alignment drift using signal weights and thresholds.
   - For `exec`-style tools, infers network scope from command indicators (for example ssh/scp/rsync/git/nc/url/ip/runtime socket usage), not just curl/wget.
   - LLM alignment treats tool params as untrusted data; relief is never applied in enforce mode, and instruction-like payloads in params increase scrutiny instead of reducing drift.
   - Returns enforcement decision.
3. `intent_output`:
   - Triggered after each tool call.
   - Scans output for instruction-like contamination.
   - Can sanitize and/or increase drift based on policy.

### 3) Drift Score and Modes

- Drift accumulates per execution.
- Thresholds define warning and blocking transitions.
- Mode behavior:
  - `off`: no drift checks.
  - `audit`: score and log only.
  - `enforce`: apply warn/block/modify outcomes.

### 4) Relationship to Prompt Injection

ClawSight addresses both direct and indirect vectors:
- Direct prompt/task mismatch: action checks.
- Tool-output contamination: output checks + sanitization.
- Trajectory drift over time: cumulative scoring across tool chain.

### 5) How Operators Tune It

- Strictness, thresholds, and mode at safety intent UI.
- Signal weight and mapping controls for domain classes/tool scopes/local-resource rules.
- Per-agent overrides when one agent needs different tolerance than global default.
- Execution decision details include scope-contribution evidence and exec network inference indicators for auditability.

## Current Limitations

- Baseline extraction can underfit broad multi-objective prompts.
- Semantic domain tags and concrete hostnames can diverge if mappings are incomplete.
- Local file strings can be misread as domains without strong local-resource rules.
- Aggressive default weights can cause false positives for valid exploratory workflows.
- LLM-assisted alignment quality depends on model selection, latency budget, and token budget.
