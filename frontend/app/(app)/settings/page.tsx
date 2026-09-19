"use client";

import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { ModelCard } from "@/lib/types";
import { ErrorNote } from "@/components/ui";

function ConfusionMatrix({ labels, matrix }: { labels: string[]; matrix: number[][] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-[13px]">
        <caption className="sr-only">Confusion matrix: rows true class, columns predicted</caption>
        <thead>
          <tr>
            <th className="label px-2 py-1.5 text-left">true ↓ / pred →</th>
            {labels.map((l) => (
              <th key={l} className="label px-2 py-1.5 text-right">{l}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {matrix.map((row, i) => (
            <tr key={labels[i]}>
              <th scope="row" className="label px-2 py-1.5 text-left font-medium">{labels[i]}</th>
              {row.map((v, j) => (
                <td
                  key={j}
                  className="tabular px-2 py-1.5 text-right font-mono"
                  style={{
                    color: i === j ? "var(--color-pass)" : v ? "var(--color-medium)" : "var(--color-faint)",
                  }}
                >
                  {v}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ModelCardPanel() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["model-card"],
    queryFn: () => api<ModelCard>("/api/model"),
  });
  if (isLoading) return <div className="card h-40 animate-pulse" />;
  if (error) return <ErrorNote message={(error as Error).message} />;
  if (!data) return null;
  const rc = data.risk_classifier;
  const ad = data.anomaly_detector;
  // published metrics may be absent (older backend / no metrics.json) —
  // the card then degrades to whatever fields exist instead of crashing
  const pct = (v: number | undefined) =>
    typeof v === "number" ? `${(v * 100).toFixed(1)}%` : "—";
  return (
    <div className="card space-y-5 p-6">
      <div>
        <h2 className="label">model card</h2>
        <p className="mt-2 text-[14px] leading-[1.5] text-subtle">
          Published training metrics for the AI layer. The risk classifier is
          trained on rule-engine-derived labels over a synthetic corpus — it
          learns published NIST/CERT-In guidance, not opinion. The anomaly
          detector is unsupervised: it learns a healthy baseline from clean
          sessions only and flags deviations with per-feature z-scores.
        </p>
      </div>
      {rc && (
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <div>
              <div className="label">model</div>
              <div className="mt-1 font-mono text-[13px]">{rc.model ?? "—"}</div>
            </div>
            <div>
              <div className="label">features</div>
              <div className="tabular mt-1 font-mono text-[13px]">{rc.features ?? "—"}</div>
            </div>
            <div>
              <div className="label">train / test</div>
              <div className="tabular mt-1 font-mono text-[13px]">
                {rc.train_size ?? "—"} / {rc.test_size ?? "—"}
              </div>
            </div>
            <div>
              <div className="label">holdout acc</div>
              <div className="tabular mt-1 font-mono text-[13px]" style={{ color: "var(--color-pass)" }}>
                {pct(rc.holdout_accuracy)}
              </div>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <div>
              <div className="label">cv acc (5-fold)</div>
              <div className="tabular mt-1 font-mono text-[13px]">{pct(rc.cv_accuracy)}</div>
            </div>
            {(["critical", "high", "medium", "low"] as const).map((c) => (
              <div key={c}>
                <div className="label">{c} F1</div>
                <div className="tabular mt-1 font-mono text-[13px]">
                  {rc.per_class?.[c] != null ? `${(rc.per_class[c].f1 * 100).toFixed(0)}%` : "—"}
                </div>
              </div>
            ))}
          </div>
          {rc.confusion_matrix?.labels && rc.confusion_matrix?.matrix && (
            <ConfusionMatrix
              labels={rc.confusion_matrix.labels}
              matrix={rc.confusion_matrix.matrix}
            />
          )}
          {rc.labeling && (
            <p className="text-[13px] leading-[1.4] text-faint">{rc.labeling}</p>
          )}
        </div>
      )}
      {ad && (
        <div className="grid grid-cols-2 gap-4 border-t border-line pt-4 sm:grid-cols-4">
          <div>
            <div className="label">anomaly model</div>
            <div className="mt-1 font-mono text-[13px]">{ad.model ?? "—"}</div>
          </div>
          <div>
            <div className="label">baseline sessions</div>
            <div className="tabular mt-1 font-mono text-[13px]">{ad.baseline_sessions ?? "—"}</div>
          </div>
          <div>
            <div className="label">flag rate (corpus)</div>
            <div className="tabular mt-1 font-mono text-[13px]">
              {ad.flag_rate_all != null ? `${(ad.flag_rate_all * 100).toFixed(1)}%` : "—"}
            </div>
          </div>
          <div>
            <div className="label">flag rate (clean)</div>
            <div className="tabular mt-1 font-mono text-[13px]">
              {ad.flag_rate_clean_baseline != null
                ? `${(ad.flag_rate_clean_baseline * 100).toFixed(1)}%`
                : "—"}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function SettingsPage() {
  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <header>
        <p className="label mb-2">system</p>
        <h1 className="text-3xl font-medium leading-[1.13] tracking-tight">Settings</h1>
      </header>

      <div className="card space-y-3 p-6">
        <h2 className="label">deployment</h2>
        <dl className="space-y-2.5 text-[14px]">
          <div className="flex justify-between gap-6">
            <dt className="text-subtle">API base</dt>
            <dd className="text-right font-mono text-[13px]">
              {process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}
            </dd>
          </div>
          <div className="flex justify-between gap-6">
            <dt className="text-subtle">Access</dt>
            <dd className="text-right font-mono text-[13px]">open — no accounts</dd>
          </div>
        </dl>
        <p className="text-[13px] leading-[1.4] text-faint">
          The analysis engine runs on a free-tier instance that sleeps when
          idle; the first request after a sleep may take up to a minute and
          retries automatically.
        </p>
      </div>

      <ModelCardPanel />
    </div>
  );
}
