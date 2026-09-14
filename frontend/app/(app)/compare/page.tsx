"use client";

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ArrowRight } from "@phosphor-icons/react/dist/ssr";
import { api } from "@/lib/api";
import type { Finding, Scan } from "@/lib/types";
import { GradeChip, SeverityBadge } from "@/components/ui";
import { ErrorNote } from "@/components/ui";

export default function ComparePage() {
  const { data } = useQuery({
    queryKey: ["scans-all"],
    queryFn: () => api<{ items: Scan[] }>("/api/scans?limit=50"),
  });
  const scans = (data?.items ?? []).filter((s) => s.status === "complete");
  const [a, setA] = useState<string>("");
  const [b, setB] = useState<string>("");

  const qa = useQuery({
    queryKey: ["compare-a", a],
    enabled: !!a,
    queryFn: () => api<{ items: Finding[]; total: number }>(`/api/scans/${a}/findings?limit=500`),
  });
  const qb = useQuery({
    queryKey: ["compare-b", b],
    enabled: !!b,
    queryFn: () => api<{ items: Finding[]; total: number }>(`/api/scans/${b}/findings?limit=500`),
  });

  const diff = useMemo(() => {
    if (!qa.data || !qb.data) return null;
    const key = (f: Finding) => `${f.rule_id}|${f.session_id}`;
    const bKeys = new Set(qb.data.items.map(key));
    const aKeys = new Set(qa.data.items.map(key));
    return {
      resolved: qa.data.items.filter((f) => !bKeys.has(key(f))),
      added: qb.data.items.filter((f) => !aKeys.has(key(f))),
    };
  }, [qa.data, qb.data]);

  const sa = scans.find((s) => s.id === a);
  const sb = scans.find((s) => s.id === b);
  const delta = sa && sb ? (sb.posture_score ?? 0) - (sa.posture_score ?? 0) : null;

  function Picker({ value, onChange, label }: { value: string; onChange: (v: string) => void; label: string }) {
    return (
      <label className="flex-1">
        <span className="text-xs uppercase tracking-wider text-subtle">{label}</span>
        <select
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="mt-1.5 w-full rounded-[var(--radius-input)] border border-line bg-paper px-3 py-2.5 text-sm"
        >
          <option value="">choose a scan…</option>
          {scans.map((s) => (
            <option key={s.id} value={s.id}>
              {s.name} ({s.posture_score}/100 {s.grade})
            </option>
          ))}
        </select>
      </label>
    );
  }

  return (
    <div className="reveal space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Compare scans</h1>
        <p className="mt-1 text-sm text-subtle">
          Track posture between captures — what got fixed, what regressed.
        </p>
      </header>

      {scans.length < 2 ? (
        <ErrorNote message="You need at least two completed scans to compare." />
      ) : (
        <>
          <div className="flex flex-col items-end gap-4 sm:flex-row">
            <Picker value={a} onChange={setA} label="Baseline" />
            <ArrowRight size={16} weight="bold" className="mb-2.5 hidden text-subtle sm:block" aria-hidden />
            <Picker value={b} onChange={setB} label="Comparison" />
          </div>

          {sa && sb && (
            <div className="card flex flex-wrap items-center gap-6 p-6">
              <div className="flex items-center gap-3">
                <GradeChip grade={sa.grade!} score={sa.posture_score!} />
                <ArrowRight size={16} weight="bold" className="text-subtle" aria-hidden />
                <GradeChip grade={sb.grade!} score={sb.posture_score!} />
              </div>
              {delta !== null && (
                <span className={`tabular text-sm ${delta >= 0 ? "text-pass" : "text-critical"}`}>
                  {delta >= 0 ? "+" : ""}{delta} points {delta >= 0 ? "improved" : "regressed"}
                </span>
              )}
            </div>
          )}

          {diff && (
            <div className="grid gap-4 lg:grid-cols-2">
              {(["resolved", "added"] as const).map((kind) => (
                <div key={kind} className="card p-5">
                  <h2 className="text-sm font-medium uppercase tracking-wider text-subtle">
                    {kind === "resolved" ? "Resolved since baseline" : "New findings"}
                  </h2>
                  <ul className="mt-3 space-y-2.5">
                    {diff[kind].length === 0 && <li className="text-sm text-faint">none</li>}
                    {diff[kind].map((f) => (
                      <li key={f.rule_id + f.session_id} className="flex flex-wrap items-center gap-2 text-sm">
                        <SeverityBadge sev={f.severity} />
                        {f.title}
                        <span className="font-mono text-xs text-faint">{f.session_id}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          )}
          {(qa.error || qb.error) && <ErrorNote message="Could not load findings for the selected scans." />}
        </>
      )}
    </div>
  );
}
