"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft } from "@phosphor-icons/react/dist/ssr";
import { api } from "@/lib/api";
import type { Advisory, Finding, Session } from "@/lib/types";
import { bytes, ms } from "@/lib/visuals";
import { CopyButton, ErrorNote, GradeChip, ProtoTag, SeverityBadge } from "@/components/ui";
import { HandshakeTimeline } from "@/components/HandshakeTimeline";
import { EvidenceFrames } from "@/components/EvidenceHex";

export default function SessionDetail() {
  const { id, sid } = useParams<{ id: string; sid: string }>();
  const { data, error, isLoading } = useQuery({
    queryKey: ["session", id, sid],
    queryFn: () => api<{ session: Session; findings: Finding[]; advisories: Advisory[] }>(
      `/api/scans/${id}/sessions/${sid}`,
    ),
  });

  if (isLoading) return <div className="card h-64 animate-pulse" />;
  if (error) return <ErrorNote message={(error as Error).message} />;
  if (!data) return null;
  const s = data.session;

  const rows: [string, string][] = [
    ["Protocol", ""],
    ["Transport", s.transport],
    ["Server", s.server_host || `${s.dst_ip}:${s.dst_port}`],
    ["Client", `${s.src_ip}:${s.src_port}`],
    ["TLS version", s.tls_version || "none — session was cleartext"],
    ["Cipher suite", s.cipher_suite || "—"],
    ["Key exchange", s.kex_mechanism || "—"],
    ["KEX group", s.negotiated_group || "—"],
    ["Forward secrecy", s.pfs === null ? "—" : s.pfs ? "yes" : "no"],
    ["Duration", ms(s.duration_ms)],
    ["Bytes", `↑ ${bytes(s.bytes_c2s)} · ↓ ${bytes(s.bytes_s2c)}`],
    ["Alerts", String(s.alert_count)],
  ];

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <Link href={`/scans/${id}`} className="inline-flex items-center gap-1.5 text-[14px] text-subtle hover:text-ink">
        <ArrowLeft size={15} aria-hidden /> Back to scan
      </Link>
      <header className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="font-mono text-xl font-semibold">{s.session_id}</h1>
        <GradeChip grade={s.grade} score={s.risk_score} />
      </header>

      <div className="card p-5">
        <h2 className="text-sm font-medium uppercase tracking-wider text-subtle">Handshake parameters</h2>
        <dl className="mt-4 space-y-2.5 text-sm">
          {rows.map(([k, v]) => (
            <div key={k} className="flex justify-between gap-6">
              <dt className="text-subtle">{k}</dt>
              <dd className="text-right font-mono text-xs leading-5">
                {k === "Protocol" ? <ProtoTag proto={s.protocol} /> : v}
                {k === "Cipher suite" && s.cipher_suite && (
                  <span className="ml-2 align-middle"><CopyButton text={s.cipher_suite} /></span>
                )}
              </dd>
            </div>
          ))}
        </dl>
      </div>

      {s.handshake_events?.length > 0 && (
        <div className="card p-5">
          <h2 className="label mb-4">handshake timeline</h2>
          <HandshakeTimeline events={s.handshake_events} />
        </div>
      )}

      {(s.ml_risk || s.is_anomaly || s.ml_adjustment !== 0) && (
        <div className="card p-5">
          <h2 className="label mb-4">ai assessment</h2>
          <div className="grid gap-4 sm:grid-cols-3">
            <div>
              <div className="label">risk class</div>
              <div className="mt-1 font-mono text-[14px]">{s.ml_risk?.label ?? "—"}</div>
              {s.ml_risk?.proba && (
                <div className="mt-1 font-mono text-[11.5px] text-faint">
                  p=[{s.ml_risk.proba.map((p) => p.toFixed(2)).join(", ")}]
                </div>
              )}
            </div>
            <div>
              <div className="label">anomaly score</div>
              <div className="tabular mt-1 font-mono text-[14px]">
                {s.is_anomaly ? s.anomaly_score.toFixed(3) : "not flagged"}
              </div>
            </div>
            <div>
              <div className="label">rule → fused</div>
              <div className="tabular mt-1 font-mono text-[14px]">
                {s.rule_score}
                {s.ml_adjustment ? ` −${s.ml_adjustment} → ${s.risk_score}` : ""}
              </div>
            </div>
          </div>
          {s.anomaly_explanation?.length > 0 && (
            <div className="mt-4 border-t border-line pt-3">
              <div className="label mb-2">why this was flagged</div>
              <ul className="space-y-1.5 text-[14px] leading-[1.4] text-subtle">
                {s.anomaly_explanation.map((t) => (
                  <li key={t.feature} className="flex items-baseline gap-2">
                    <span
                      className="inline-block h-1.5 w-1.5 shrink-0 rounded-full"
                      style={{ background: Math.abs(t.z) > 2 ? "var(--color-medium)" : "var(--color-faint)" }}
                      aria-hidden
                    />
                    <span>
                      <span className="font-mono text-[13px]">{t.feature.replace(/_/g, " ")}</span>{" "}
                      sits <b className="font-mono">{t.z > 0 ? "+" : ""}{t.z}σ</b>{" "}
                      from the healthy baseline (observed {t.value}).
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {s.reassembly_incomplete && (
        <div className="card p-5" role="alert">
          <h2 className="label mb-2" style={{ color: "var(--color-medium)" }}>
            tcp reassembly incomplete
          </h2>
          <p className="text-[14px] leading-[1.4] text-subtle">
            This session&apos;s byte stream had a gap — one or more TCP
            segments never arrived in the capture. The analysis covers the
            contiguous portion only; the forensic record stops at the hole
            rather than fabricating contiguity.
          </p>
        </div>
      )}

      {s.cleartext_creds?.length > 0 && (
        <div className="card border-[var(--color-critical)] p-5" role="alert">
          <h2 className="label mb-3" style={{ color: "var(--color-critical)" }}>
            cleartext credentials observed (redacted)
          </h2>
          <ul className="space-y-2 text-[14px]">
            {s.cleartext_creds.map((c, i) => (
              <li key={i} className="flex flex-wrap items-center gap-2">
                <span className="rounded-[3px] px-1.5 font-mono text-[12.5px]" style={{ background: "var(--color-critical-bg)", color: "var(--color-critical)" }}>
                  {c.kind}
                </span>
                {c.user && <span className="font-mono text-[13px]">{c.user}</span>}
                {c.password && <span className="font-mono text-[13px] text-faint">{c.password}</span>}
              </li>
            ))}
          </ul>
        </div>
      )}

      {(s.frames_c2s?.length || 0) + (s.frames_s2c?.length || 0) > 0 && (
        <div className="card p-5">
          <h2 className="label mb-3">pcap frames carrying this session</h2>
          <div className="space-y-3">
            <EvidenceFrames frames={s.frames_c2s} />
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="label">client</span>
              {s.frames_c2s.slice(0, 10).map((f) => (
                <span key={f} className="tabular rounded-[3px] bg-raised px-1.5 py-0.5 font-mono text-[12.5px] text-subtle">{f}</span>
              ))}
            </div>
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="label">server</span>
              {s.frames_s2c.slice(0, 10).map((f) => (
                <span key={f} className="tabular rounded-[3px] bg-raised px-1.5 py-0.5 font-mono text-[12.5px] text-subtle">{f}</span>
              ))}
            </div>
          </div>
        </div>
      )}

      <section aria-label="Findings for this session">
        <h2 className="mb-3 text-sm font-medium uppercase tracking-wider text-subtle">
          Findings ({data.findings.length})
        </h2>
        <div className="space-y-2">
          {data.findings.length === 0 && (
            <p className="card px-4 py-6 text-center text-sm text-faint">
              This session passed every rule.
            </p>
          )}
          {data.findings.map((f) => (
            <div key={f.rule_id} className="card px-4 py-3">
              <div className="flex flex-wrap items-center gap-3">
                <SeverityBadge sev={f.severity} />
                <span className="font-medium">{f.title}</span>
                <span className="ml-auto font-mono text-xs text-faint">{f.rule_id}</span>
              </div>
              <p className="mt-1.5 text-sm text-subtle">{f.description}</p>
              <p className="mt-1 text-sm text-subtle"><span className="text-faint">Fix: </span>{f.remediation}</p>
            </div>
          ))}
        </div>
      </section>

      {data.advisories?.length ? (
        <section aria-label="Advisories for this session">
          <h2 className="mb-3 text-sm font-medium uppercase tracking-wider text-subtle">
            Advisories ({data.advisories.length}) — informational, not scored
          </h2>
          <div className="space-y-2">
            {data.advisories.map((a) => (
              <div key={a.rule_id} className="card px-4 py-3">
                <div className="flex flex-wrap items-center gap-3">
                  <span className="label rounded-[4px] border border-line px-2 py-0.5 text-xs text-subtle">info</span>
                  <span className="font-medium">{a.title}</span>
                  <span className="ml-auto font-mono text-xs text-faint">{a.rule_id}</span>
                </div>
                <p className="mt-1.5 text-sm text-subtle">{a.description}</p>
                <p className="mt-1 text-sm text-subtle"><span className="text-faint">Guidance: </span>{a.remediation}</p>
              </div>
            ))}
          </div>
        </section>
      ) : null}
    </div>
  );
}
