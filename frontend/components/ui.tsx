"use client";

import { Hue } from "@/lib/visuals";

function hueOf(grade: string): Hue {
  if (grade === "A") return "pass";
  if (grade === "B") return "low";
  if (grade === "C") return "medium";
  if (grade === "D") return "high";
  return "critical";
}

export function SeverityBadge({ sev }: { sev: Hue }) {
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-[4px] px-2 py-0.5 font-mono text-[13px] font-medium leading-[1.4]"
      style={{ background: `var(--color-${sev}-bg)`, color: `var(--color-${sev})` }}
    >
      <span
        className="inline-block h-1.5 w-1.5 rounded-[1px]"
        style={{ background: `var(--color-${sev})` }}
        aria-hidden
      />
      {sev}
    </span>
  );
}

export function GradeChip({ grade, score }: { grade: string; score?: number }) {
  const hue = hueOf(grade);
  return (
    <span
      className="tabular inline-flex items-center gap-1.5 rounded-[4px] px-2 py-0.5 font-mono text-[13px] font-medium leading-[1.4]"
      style={{ background: `var(--color-${hue}-bg)`, color: `var(--color-${hue})` }}
      title={`Score ${score ?? "—"}/100`}
    >
      {grade}
      {score !== undefined && <span className="opacity-75">{score}</span>}
    </span>
  );
}

export function StatCard({ label, value, delta }: { label: string; value: string | number; delta?: string }) {
  return (
    <div className="card p-5">
      <div className="label">{label}</div>
      <div className="tabular mt-2.5 text-[26px] font-medium leading-none">{value}</div>
      {delta && <div className="mt-2 truncate text-[13px] leading-[1.25] text-faint">{delta}</div>}
    </div>
  );
}

export function EmptyState({ message, action }: { message: string; action?: React.ReactNode }) {
  return (
    <div className="card flex flex-col items-center gap-4 px-6 py-16 text-center">
      <p className="max-w-md text-[15px] leading-[1.25] text-subtle">{message}</p>
      {action}
    </div>
  );
}

export function ErrorNote({ message }: { message: string }) {
  return (
    <div
      role="alert"
      className="rounded-[6px] px-4 py-3 text-[14px] leading-[1.25]"
      style={{ background: "var(--color-critical-bg)", color: "var(--color-critical)" }}
    >
      {message}
    </div>
  );
}

export function ProtoTag({ proto }: { proto: string }) {
  return (
    <span className="rounded-[3px] bg-raised px-1.5 py-0.5 font-mono text-[13px] leading-[1.4] text-subtle">
      {proto}
    </span>
  );
}

export function CopyButton({ text }: { text: string }) {
  return (
    <button
      type="button"
      className="rounded-[3px] px-1.5 py-0.5 font-mono text-[13px] leading-[1.4] text-faint transition-colors hover:text-ink"
      onClick={(e) => {
        navigator.clipboard.writeText(text);
        const el = e.currentTarget;
        el.textContent = "copied";
        setTimeout(() => (el.textContent = "copy"), 1500);
      }}
    >
      copy
    </button>
  );
}
