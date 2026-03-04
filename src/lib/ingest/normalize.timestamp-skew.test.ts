import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { normalizeTelemetryEvent } from "@/lib/ingest/normalize";

const NOW = new Date("2026-03-04T12:00:00.000Z").getTime();
const ONE_HOUR_MS = 60 * 60 * 1000;
const ONE_DAY_MS = 24 * ONE_HOUR_MS;
const FIVE_MIN_MS = 5 * 60 * 1000;

describe("normalizeTelemetryEvent timestamp skew guard", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("clamps overly old client timestamps to bounded past skew", () => {
    const envelope = normalizeTelemetryEvent({
      ts: NOW - 120 * ONE_DAY_MS,
      category: "tool",
      action: "exec",
    });

    expect(envelope.row.ts).toBeInstanceOf(Date);
    expect((envelope.row.ts as Date).getTime()).toBe(NOW - ONE_DAY_MS);
  });

  it("clamps far-future client timestamps to bounded future skew", () => {
    const envelope = normalizeTelemetryEvent({
      ts: NOW + ONE_DAY_MS,
      category: "tool",
      action: "exec",
    });

    expect(envelope.row.ts).toBeInstanceOf(Date);
    expect((envelope.row.ts as Date).getTime()).toBe(NOW + FIVE_MIN_MS);
  });

  it("keeps in-range client timestamps unchanged", () => {
    const inRange = NOW - 2 * ONE_HOUR_MS;
    const envelope = normalizeTelemetryEvent({
      ts: inRange,
      category: "message",
      action: "user.input",
    });

    expect((envelope.row.ts as Date).getTime()).toBe(inRange);
  });
});
