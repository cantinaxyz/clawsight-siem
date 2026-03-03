/**
 * @fileoverview ClawSight SIEM module: platform/src/components/ui/token-list-input.tsx.
 */
"use client";

import * as React from "react";
import { X } from "lucide-react";
import { cn } from "@/lib/utils";

type TokenListInputProps = {
  name: string;
  label: string;
  defaultValues?: string[];
  placeholder?: string;
  hint?: string;
  className?: string;
};

function unique(values: string[]): string[] {
  const seen = new Set<string>();
  const ordered: string[] = [];
  for (const raw of values) {
    const value = raw.trim();
    if (!value) continue;
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    ordered.push(value);
  }
  return ordered;
}

function parseValues(raw: string): string[] {
  return unique(raw.split(/[,\n]/).map((value) => value.trim()));
}

export default function TokenListInput({
  name,
  label,
  defaultValues = [],
  placeholder = "Type and press Enter",
  hint = "Use Enter or comma to add.",
  className,
}: TokenListInputProps) {
  const [values, setValues] = React.useState<string[]>(() => unique(defaultValues));
  const [draft, setDraft] = React.useState("");

  const commitDraft = React.useCallback(() => {
    const next = parseValues(draft);
    if (next.length > 0) {
      setValues((current) => unique([...current, ...next]));
    }
    setDraft("");
  }, [draft]);

  return (
    <div className={cn("rounded-md border border-border bg-card px-3 py-2", className)}>
      <input type="hidden" name={name} value={values.join(", ")} readOnly />
      <p className="mb-2 text-xs font-medium text-muted-foreground">{label}</p>
      <div className="flex min-h-[32px] flex-wrap items-center gap-1.5 rounded-md border border-border bg-secondary px-2 py-1.5">
        {values.map((value) => (
          <span
            key={value}
            className="inline-flex items-center gap-1 rounded bg-accent px-2 py-0.5 font-mono text-xs text-foreground"
          >
            <span className="max-w-[16rem] truncate">{value}</span>
            <button
              type="button"
              className="text-muted-foreground transition-colors hover:text-foreground"
              onClick={() => setValues((current) => current.filter((item) => item !== value))}
              aria-label={`Remove ${value}`}
            >
              <X className="h-3 w-3" />
            </button>
          </span>
        ))}
        <input
          type="text"
          value={draft}
          placeholder={values.length === 0 ? placeholder : "Add..."}
          className="min-w-[120px] flex-1 border-0 bg-transparent p-0 text-xs text-foreground outline-none placeholder:text-muted-foreground"
          onChange={(event) => setDraft(event.target.value)}
          onBlur={commitDraft}
          onKeyDown={(event) => {
            if (event.key === "Enter" || event.key === ",") {
              event.preventDefault();
              commitDraft();
            }
          }}
        />
      </div>
      <p className="mt-1.5 text-xs text-muted-foreground">{hint}</p>
    </div>
  );
}
