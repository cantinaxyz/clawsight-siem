/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/telemetry-display.ts.
 */
type PayloadRecord = Record<string, unknown> | null;

export type DisplayField = {
  label: string;
  value: string;
};

export type TelemetryDisplayModel = {
  title: string;
  summary?: string;
  fields: DisplayField[];
  artifacts: DisplayArtifact[];
  payload: unknown;
};

export type DisplayArtifact = {
  kind: "file" | "url" | "media";
  label?: string;
  mimeType?: string;
  fileName?: string;
  filePath?: string;
  url?: string;
  source: string;
};

type TelemetryDisplayInput = {
  category?: string | null;
  action?: string | null;
  stage?: string | null;
  payload?: unknown;
  payloadRedacted?: unknown;
  payloadSummary?: unknown;
  toolName?: string | null;
  outcomeReason?: string | null;
};

function asRecord(value: unknown): PayloadRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function asString(value: unknown): string | undefined {
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return undefined;
}

function preview(text: string, max = 220): string {
  return text.length <= max ? text : `${text.slice(0, max)}...`;
}

function previewJson(value: unknown, max = 220): string {
  if (value == null) return "-";
  if (typeof value === "string") return preview(value, max);
  try {
    const raw = JSON.stringify(value);
    return raw.length <= max ? raw : `${raw.slice(0, max)}...`;
  } catch {
    return preview(String(value), max);
  }
}

function getMessageText(payload: PayloadRecord): string | undefined {
  if (!payload) return undefined;
  const bodyRec = asRecord(payload.body);
  const contentRec = asRecord(payload.content);
  const textRec = asRecord(payload.text);
  return (
    asString(payload.body) ||
    asString(payload.content) ||
    asString(payload.text) ||
    asString(bodyRec?.preview) ||
    asString(contentRec?.preview) ||
    asString(textRec?.preview) ||
    asString(payload.prompt)
  );
}

function maybeArtifact(rec: Record<string, unknown>, source: string): DisplayArtifact | null {
  const filePath =
    asString(rec.file_path) ??
    asString(rec.filePath) ??
    asString(rec.path) ??
    asString(rec.mediaPath);
  const url =
    asString(rec.url) ??
    asString(rec.mediaUrl) ??
    asString(rec.href);
  const fileName =
    asString(rec.file_name) ??
    asString(rec.fileName) ??
    asString(rec.filename) ??
    asString(rec.name);
  const mimeType =
    asString(rec.mime_type) ??
    asString(rec.mimeType) ??
    asString(rec.mimetype) ??
    asString(rec.contentType) ??
    asString(rec.type);
  const label =
    asString(rec.label) ??
    asString(rec.kind) ??
    asString(rec.mediaType) ??
    asString(rec.type);
  if (!filePath && !url && !fileName && !mimeType) {
    return null;
  }
  return {
    kind: filePath ? "file" : (url ? "url" : "media"),
    label,
    mimeType,
    fileName,
    filePath,
    url,
    source,
  };
}

function pushArtifact(
  out: DisplayArtifact[],
  seen: Set<string>,
  artifact: DisplayArtifact | null,
) {
  if (!artifact) return;
  const key = [
    artifact.kind,
    artifact.filePath ?? "",
    artifact.url ?? "",
    artifact.fileName ?? "",
    artifact.mimeType ?? "",
    artifact.source,
  ].join("|");
  if (seen.has(key)) return;
  seen.add(key);
  out.push(artifact);
}

function collectArtifactsFromUnknown(
  value: unknown,
  source: string,
  out: DisplayArtifact[],
  seen: Set<string>,
  depth = 0,
) {
  if (depth > 4) return;
  if (Array.isArray(value)) {
    for (const item of value.slice(0, 40)) {
      collectArtifactsFromUnknown(item, source, out, seen, depth + 1);
    }
    return;
  }
  const rec = asRecord(value);
  if (!rec) return;

  pushArtifact(out, seen, maybeArtifact(rec, source));

  const candidateKeys = [
    "artifacts",
    "attachments",
    "media",
    "files",
    "file",
    "documents",
    "document",
    "photos",
    "photo",
    "items",
    "mediaItems",
    "params",
    "payload",
    "metadata",
    "context",
  ];
  for (const key of candidateKeys) {
    if (!(key in rec)) continue;
    collectArtifactsFromUnknown(rec[key], `${source}.${key}`, out, seen, depth + 1);
  }
}

function collectPromptMediaMarkers(
  text: string | undefined,
  out: DisplayArtifact[],
  seen: Set<string>,
) {
  if (!text) return;
  const markerRe = /\[media attached:\s*([^\]]+?)\]/gi;
  let match: RegExpExecArray | null = markerRe.exec(text);
  let count = 0;
  while (match && count < 12) {
    const marker = match[1]?.trim();
    if (marker) {
      const mimeMatch = marker.match(/\(([^()]+\/[^()]+)\)/);
      const mimeType = mimeMatch?.[1]?.trim();
      const beforeParen = marker.replace(/\s*\([^)]*\)\s*/g, " ").trim();
      const candidate = beforeParen.split(/\s+/)[0] ?? beforeParen;
      const fileName = candidate.includes(".") ? candidate : undefined;
      pushArtifact(out, seen, {
        kind: "media",
        label: marker,
        mimeType,
        fileName,
        source: "payload.promptPreview",
      });
      count += 1;
    }
    match = markerRe.exec(text);
  }
}

function extractArtifacts(payload: PayloadRecord): DisplayArtifact[] {
  if (!payload) return [];
  const out: DisplayArtifact[] = [];
  const seen = new Set<string>();
  collectArtifactsFromUnknown(payload, "payload", out, seen);
  collectPromptMediaMarkers(asString(payload.promptPreview) ?? asString(payload.prompt), out, seen);
  return out.slice(0, 24);
}

function artifactLabel(artifact: DisplayArtifact): string {
  const primary =
    artifact.fileName ??
    artifact.filePath ??
    artifact.url ??
    artifact.label ??
    artifact.mimeType ??
    artifact.kind;
  if (artifact.mimeType && primary !== artifact.mimeType) {
    return `${primary} (${artifact.mimeType})`;
  }
  return primary;
}

function getToolArgsPreview(payload: PayloadRecord): string | undefined {
  if (!payload) return undefined;
  const params = asRecord(payload.params);
  if (!params) return undefined;
  const command = asString(params.command);
  if (command) return command;
  const commandRec = asRecord(params.command);
  const commandPreview =
    asString(commandRec?.preview) ||
    asString(commandRec?.command) ||
    asString(commandRec?.value);
  if (commandPreview) return commandPreview;
  const path = asString(params.path);
  if (path) return `path=${path}`;
  const filePath = asString(params.file_path);
  if (filePath) return `file_path=${filePath}`;
  const tool = asString(payload.toolName);
  return tool ? previewJson(params, 180) : undefined;
}

function pushField(fields: DisplayField[], label: string, value?: unknown, max = 220) {
  if (value == null) return;
  const str = typeof value === "string" ? value.trim() : String(value);
  if (!str) return;
  fields.push({ label, value: preview(str, max) });
}

function parseActionSpecific(
  key: string,
  payload: PayloadRecord,
  fallbackToolName?: string | null,
): { summary?: string; fields: DisplayField[] } {
  const fields: DisplayField[] = [];

  if (key === "message.received" || key === "message.sending" || key === "message.sent") {
    pushField(fields, "from", payload ? payload.from : undefined);
    pushField(fields, "to", payload ? payload.to : undefined);
    pushField(fields, "channel", payload ? payload.channelId : undefined);
    pushField(fields, "conversation", payload ? payload.conversationId : undefined);
    pushField(fields, "len", payload ? payload.len : undefined);
    pushField(fields, "bodySha256", payload ? payload.bodySha256 : undefined);
    const text = getMessageText(payload);
    if (text) {
      return { summary: preview(text), fields };
    }
    return { summary: "message text unavailable (legacy hashed payload)", fields };
  }

  if (key === "session.llm_input") {
    pushField(fields, "provider", payload ? payload.provider : undefined);
    pushField(fields, "model", payload ? payload.model : undefined);
    pushField(fields, "runId", payload ? payload.runId : undefined);
    pushField(fields, "history", payload ? payload.historyMessageCount : undefined);
    pushField(fields, "images", payload ? payload.imagesCount : undefined);
    const prompt =
      asString(payload ? payload.prompt : undefined) || getMessageText(payload);
    return { summary: prompt ? preview(prompt) : undefined, fields };
  }

  if (key === "session.llm_output") {
    pushField(fields, "provider", payload ? payload.provider : undefined);
    pushField(fields, "model", payload ? payload.model : undefined);
    pushField(fields, "runId", payload ? payload.runId : undefined);
    const usage = payload ? asRecord(payload.usage) : null;
    if (usage) {
      pushField(fields, "input", usage.input ?? usage.inputTokens);
      pushField(fields, "output", usage.output ?? usage.outputTokens);
      pushField(fields, "total", usage.total ?? usage.totalTokens);
    }
    const assistantTexts = payload?.assistantTexts;
    if (Array.isArray(assistantTexts) && assistantTexts.length > 0) {
      return { summary: preview(String(assistantTexts[0] ?? "")), fields };
    }
    return { summary: asString(payload ? payload.text : undefined), fields };
  }

  if (key === "tool.before_tool_call" || key === "tool.after_tool_call" || key === "tool.tool_result_persist") {
    const toolName = asString(payload ? payload.toolName : undefined) || fallbackToolName || undefined;
    pushField(fields, "tool", toolName);
    pushField(fields, "toolCallId", payload ? payload.toolCallId : undefined);
    pushField(fields, "durationMs", payload ? payload.durationMs : undefined);
    pushField(fields, "status", payload ? payload.status : undefined);
    pushField(fields, "error", payload ? payload.error : undefined);

    const argsPreview = getToolArgsPreview(payload);
    if (argsPreview) {
      pushField(fields, "command", argsPreview, 10_000);
      return { summary: preview(argsPreview), fields };
    }
    const resultPreview = payload?.result;
    if (resultPreview !== undefined) {
      return { summary: previewJson(resultPreview, 220), fields };
    }
    return { summary: undefined, fields };
  }

  if (key === "agent.bootstrap") {
    const profile = payload ? asRecord(payload.agentProfile) : null;
    pushField(fields, "agentName", profile ? profile.agentName : payload ? payload.agentName : undefined);
    pushField(fields, "agentInstanceId", profile ? profile.agentInstanceId : payload ? payload.agentInstanceId : undefined);
    pushField(fields, "host", profile ? profile.hostName : payload ? payload.hostName : undefined);
    pushField(fields, "os", profile ? profile.osPlatform : payload ? payload.osPlatform : undefined);
    pushField(fields, "node", profile ? profile.nodeVersion : payload ? payload.nodeVersion : undefined);
    pushField(fields, "openclaw", profile ? profile.openclawVersion : payload ? payload.openclawVersion : undefined);
    pushField(fields, "plugin", profile ? profile.pluginVersion : payload ? payload.pluginVersion : undefined);
    const summary =
      asString(profile ? profile.agentName : undefined) ||
      asString(payload ? payload.agentName : undefined) ||
      asString(profile ? profile.agentInstanceId : undefined);
    return { summary, fields };
  }

  if (key === "session.before_agent_start" || key === "session.agent_end") {
    pushField(fields, "runId", payload ? payload.runId : undefined);
    pushField(fields, "sessionId", payload ? payload.sessionId : undefined);
    pushField(fields, "durationMs", payload ? payload.durationMs : undefined);
    pushField(fields, "success", payload ? payload.success : undefined);
    pushField(fields, "messages", payload ? payload.messageCount : undefined);
    return { summary: undefined, fields };
  }

  return { summary: undefined, fields };
}

/**
 * Builds a normalized display model for telemetry rows in UI tables/details.
 *
 * It collapses heterogeneous payload shapes into a stable title/summary/fields/artifacts
 * structure so the UI can render events consistently without endpoint-specific logic.
 */
export function buildTelemetryDisplay(input: TelemetryDisplayInput): TelemetryDisplayModel {
  const payload =
    input.payload ??
    input.payloadSummary ??
    input.payloadRedacted ??
    null;
  const record = asRecord(payload);
  const category = String(input.category || "").trim();
  const action = String(input.action || "").trim();
  const stage = String(input.stage || "").trim();
  const key = `${category}.${action}`;
  const title = action && category ? key : stage || "event";

  const parsed = parseActionSpecific(key, record, input.toolName);
  const fields = [...parsed.fields];
  const artifacts = extractArtifacts(record);

  if (input.outcomeReason) {
    fields.push({ label: "reason", value: preview(input.outcomeReason, 220) });
  }

  if (artifacts.length > 0) {
    fields.push({ label: "artifacts", value: String(artifacts.length) });
    for (const artifact of artifacts.slice(0, 2)) {
      fields.push({
        label: artifact.kind === "file" ? "file" : (artifact.kind === "url" ? "url" : "media"),
        value: preview(artifactLabel(artifact), 220),
      });
    }
  }

  if (fields.length === 0 && record) {
    const fallbackKeys = [
      "hook",
      "toolName",
      "toolCallId",
      "requestId",
      "runId",
      "sessionId",
      "sessionKey",
      "provider",
      "model",
      "durationMs",
      "error",
      "status",
    ];
    for (const k of fallbackKeys) {
      if (!(k in record)) continue;
      const value = record[k];
      if (value == null) continue;
      fields.push({ label: k, value: previewJson(value, 220) });
    }
  }

  return {
    title,
    summary: parsed.summary,
    fields,
    artifacts,
    payload,
  };
}
