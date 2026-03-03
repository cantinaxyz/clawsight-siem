/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/executions/types.ts.
 */
export type TriggerType = "user" | "cron" | "webhook" | "retry" | "chain" | "system";

export type ExecutionOutcome = "completed" | "error" | "blocked" | "running";

export type ExecutionRollup = {
  toolCalls: number;
  domainsTouched: number;
  errors: number;
  alertsRaised: number;
};

export type ExecutionIntentSummary = {
  baselineExtracted: boolean;
  currentDriftScore: number;
  driftStatus: "normal" | "elevated" | "high" | "blocked";
  decisionsCount: number;
  warnsCount: number;
  blocksCount: number;
  sanitizedCount: number;
};

export type Execution = {
  executionId: string;
  traceId: string;
  agentKey: string;
  agentName: string;
  triggerType: TriggerType;
  triggerSource: string;
  triggerRef?: string;
  outcome: ExecutionOutcome;
  startedAt: string;
  endedAt?: string;
  durationMs?: number;
  rootExecutionId?: string;
  parentExecutionId?: string;
  channelsInvolved?: string[];
  intentSummary?: ExecutionIntentSummary;
  rollup: ExecutionRollup;
};

export type ExecutionLineageNode = {
  executionId: string;
  traceId: string;
  triggerType: TriggerType;
  outcome: ExecutionOutcome;
  durationMs?: number;
  startedAt: string;
  children: ExecutionLineageNode[];
};
