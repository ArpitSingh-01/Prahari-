"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Warning, DownloadSimple } from "@phosphor-icons/react/dist/ssr";
import { api, downloadReport } from "@/lib/api";
import type { Advisory, Certificate, Finding, Scan, ScanResult, Session } from "@/lib/types";
import { useToasts } from "@/components/Toast";import { SEVERITIES, bytes, severityHue } from "@/lib/visuals";
import { CopyButton, EmptyState, ErrorNote, GradeChip, ProtoTag, SeverityBadge, StatCard } from "@/components/ui";
import { ScoreDial } from "@/components/ScoreDial";
import { EvidenceHex, EvidenceFrames } from "@/components/EvidenceHex";

const TABS = ["Overview", "Sessions", "Findings", "Certificates", "Anomalies", "Compliance", "Reports"] as const;
type Tab = (typeof TABS)[number];

export default function ScanWorkspace() {
  const { id } = useParams<{ id: string }>();
  const [tab, setTab] = useState<Tab>("Overview");

  const scanQ = useQuery({
    queryKey: ["scan", id],
    queryFn: () => api<Scan>(`/api/scans/${id}`),
    refetchInterval: (q) =>
      q.state.data && ["uploaded", "parsing"].includes(q.state.data.status) ? 2000 : false,
  });
  const resQ = useQuery({
    queryKey: ["scan", id, "full"],
    queryFn: async () => {
      const [sessions, findings, advisories, certificates, anomalies, summary] = await Promise.all([
        api<{ items: Session[] }>(`/api/scans/${id}/sessions?limit=200`),
        api<{ items: Finding[] }>(`/api/scans/${id}/findings?limit=500`),
        api<{ items: Advisory[] }>(`/api/scans/${id}/advisories?limit=500`),
        api<{ items: Certificate[] }>(`/api/scans/${id}/certificates`),
        api<{ items: (Session & { explanation: { top_features: { feature: string; value: number; z: number }[] } })[] }>(`/api/scans/${id}/anomalies`),
        api<{ summary: string; posture: ScanResult["posture"] }>(`/api/scans/${id}/summary`),
      ]);
      return {
        sessions: sessions.items,
        findings: findings.items,
        advisories: advisories.items,
        certificates: certificates.items,
        anomalies: anomalies.items,
        summary: summary.summary,
        posture: summary.posture,
      };
    },
    enabled: scanQ.data?.status === "complete",
  });

  const scan = scanQ.data;
  if (scanQ.isLoading) return <div className="card h-64 animate-pulse" />;
  if (scanQ.error) return <ErrorNote message={(scanQ.error as Error).message} />;
  if (!scan) return null;

  if (scan.status !== "complete") {
    return (
      <div className="reveal mx-auto max-w-xl space-y-6 py-16 text-center">
        <h1 className="text-xl font-semibold">{scan.name}</h1>
        {scan.status === "failed" ? (
          <ErrorNote message={`Analysis failed: ${scan.error || "unknown error"}`} />
        ) : (
          <>
            <div className="pulsing font-mono text-accent">analyzing… {scan.progress}%</div>
            <div className="h-2 overflow-hidden rounded-full bg-raised" role="progressbar" aria-valuenow={scan.progress} aria-valuemin={0} aria-valuemax={100}>
              <div className="h-full rounded-full bg-accent transition-all" style={{ width: `${scan.progress}%` }} />
            </div>
            <p className="text-sm text-subtle">
              Reconstructing sessions and handshakes. If the engine was
              asleep, the first steps can take up to a minute — this page
              keeps polling and picks up the moment it&apos;s ready.
            </p>
          </>
        )}
      </div>
    );
  }

  return (
    <div className="reveal space-y-6">
      <header className="card flex flex-wrap items-center gap-6 p-6">
        <ScoreDial score={scan.posture_score ?? 0} grade={scan.grade ?? "F"} />
        <div className="min-w-0 flex-1">
          <h1 className="truncate text-xl font-semibold">{scan.name}</h1>
          <p className="mt-1 text-sm text-subtle">
            {bytes(scan.file_size)} · {scan.session_count} sessions ·{" "}
            {Object.entries(scan.protocol_counts).map(([k, v]) => `${k} ${v}`).join(", ") || "no mail protocols"}
          </p>
          <p className="mt-1 text-xs text-faint">
            analyzed {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : "—"}
          </p>
        </div>
      </header>

      <nav className="flex gap-1 overflow-x-clip rounded-[8px] border border-white/[0.07] bg-surface p-1" role="tablist" aria-label="Scan views">
        {TABS.map((t) => (
          <button
            key={t}
            role="tab"
            aria-selected={tab === t}
            onClick={() => setTab(t)}
            className={`whitespace-nowrap rounded-[6px] px-4 py-2 text-[14px] transition-colors ${
              tab === t ? "bg-raised font-medium text-ink" : "text-subtle hover:text-ink"
            }`}
          >
            {t}
            {t === "Anomalies" && resQ.data && resQ.data.anomalies.length > 0 && (
              <span className="tabular ml-1.5 text-xs opacity-80">{resQ.data.anomalies.length}</span>
            )}
          </button>
        ))}
      </nav>

      {resQ.isLoading && <div className="card h-40 animate-pulse" />}
      {resQ.error && <ErrorNote message={(resQ.error as Error).message} />}
      {resQ.data && (
        <>
          {tab === "Overview" && <Overview scan={scan} data={resQ.data} />}
          {tab === "Sessions" && <SessionsTable scanId={id} sessions={resQ.data.sessions} />}
          {tab === "Findings" && <FindingsList findings={resQ.data.findings} />}
          {tab === "Certificates" && <CertsList certs={resQ.data.certificates} />}
          {tab === "Anomalies" && <AnomaliesList anomalies={resQ.data.anomalies} />}
          {tab === "Compliance" && <ComplianceView findings={resQ.data.findings} />}
          {tab === "Reports" && <Reports scanId={id} />}
        </>
      )}
    </div>
  );
}

function Overview({
  scan,
  data,
}: {
  scan: Scan;
  data: { sessions: Session[]; findings: Finding[]; advisories: Advisory[]; certificates: Certificate[]; anomalies: (Session & { explanation: { top_features: { feature: string; value: number; z: number }[] } })[]; summary: string; posture: ScanResult["posture"] };
}) {
  const sev = data.findings.reduce<Record<string, number>>((m, f) => {
    m[f.severity] = (m[f.severity] ?? 0) + 1;
    return m;
  }, {});
  const chartData = SEVERITIES.filter((s) => sev[s]).map((s) => ({ severity: s, count: sev[s] }));
  const top = [...data.findings].sort((a, b) => b.weight - a.weight).slice(0, 5);
  const pqc = data.posture?.pqc;
  const credsExposed = data.posture?.credential_exposure;
  const ml = data.posture?.ml;
  const riskDist = ml?.risk_distribution ?? {};
  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-4">
        <StatCard label="critical" value={sev.critical ?? 0} />
        <StatCard label="high" value={sev.high ?? 0} />
        <StatCard label="medium" value={sev.medium ?? 0} />
        <StatCard label="low" value={sev.low ?? 0} />
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        <StatCard
          label="quantum-vulnerable sessions"
          value={pqc?.quantum_vulnerable_sessions ?? "—"}
          delta="classical key exchange — no PQC migration path (harvest-now-decrypt-later)"
        />
        <StatCard
          label="cleartext credential sessions"
          value={credsExposed ?? "—"}
          delta="usernames and passwords sent before TLS or without TLS (redacted in evidence)"
        />
      </div>
      {(pqc?.pqc_ready_sessions ?? 0) > 0 || (data.advisories?.length ?? 0) > 0 ? (
        <div className="card p-5">
          <h2 className="label">post-quantum readiness</h2>
          <div className="mt-4 grid gap-4 sm:grid-cols-2">
            <StatCard
              label="PQC-ready sessions (hybrid ML-KEM)"
              value={pqc?.pqc_ready_sessions ?? 0}
              delta="negotiated X25519MLKEM768 / SecP256r1MLKEM768 — post-quantum secure key establishment"
            />
          </div>
          {data.advisories?.length ? (
            <ul className="mt-4 space-y-2 border-t border-line pt-4">
              {data.advisories.slice(0, 8).map((a) => (
                <li key={`${a.session_id}-${a.rule_id}`} className="text-[13px] leading-[1.5] text-subtle">
                  <span className="font-mono text-faint">{a.session_id}</span>{" "}
                  <span className="text-ink">{a.title}</span> — {a.description}
                </li>
              ))}
            </ul>
          ) : null}
          <p className="mt-3 text-[13px] leading-[1.4] text-faint">
            Advisories are informational: being quantum-vulnerable today is the
            industry status quo, not a misconfiguration — it is reported for
            migration planning and carries zero score weight.
          </p>
        </div>
      ) : null}
      <div className="card p-5">
        <h2 className="label">ai layer</h2>
        {ml?.enabled ? (
          <div className="mt-4 grid grid-cols-2 gap-4 sm:grid-cols-4">
            <div>
              <div className="label">anomalous sessions</div>
              <div className="tabular mt-1 text-[22px] font-medium">{ml.anomalous_sessions}</div>
            </div>
            <div>
              <div className="label">risk distribution</div>
              <div className="mt-1 space-y-0.5 font-mono text-[13px] leading-[1.5]">
                {Object.entries(riskDist).map(([k, v]) => (
                  <div key={k} className="flex justify-between gap-3">
                    <span className="text-subtle">{k}</span>
                    <span className="tabular">{v}</span>
                  </div>
                ))}
                {!Object.keys(riskDist).length && <span className="text-faint">—</span>}
              </div>
            </div>
            <div>
              <div className="label">rule score</div>
              <div className="tabular mt-1 text-[22px] font-medium">
                {data.posture?.rule_score ?? scan.posture_score ?? "—"}
              </div>
            </div>
            <div>
              <div className="label">AI adjustment → fused</div>
              <div className="tabular mt-1 text-[22px] font-medium">
                {data.posture?.ml_adjustment
                  ? `−${data.posture.ml_adjustment} → ${data.posture.score}`
                  : `0 → ${data.posture?.score ?? "—"}`}
              </div>
            </div>
          </div>
        ) : (
          <p className="mt-3 text-sm leading-[1.4] text-subtle">
            The AI layer was unavailable for this scan — the rule engine
            results are unaffected and fully authoritative on their own.
          </p>
        )}
        <p className="mt-4 border-t border-line pt-3 text-[13px] leading-[1.4] text-faint">
          Fusion is bounded: each session contributes at most 2 points, the
          scan at most 10, and only downward from the rule score. The AI can
          deepen a verdict the rules already imply; it never softens one, and
          a clean capture stays exactly 100/A.
        </p>
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="card p-5">
          <h2 className="text-sm font-medium uppercase tracking-wider text-subtle">Findings by severity</h2>
          <div className="mt-4 h-48">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData}>
                <CartesianGrid vertical={false} stroke="var(--color-rule)" />
                <XAxis dataKey="severity" tick={{ fill: "var(--color-subtle)", fontSize: 12 }} axisLine={false} tickLine={false} />
                <YAxis allowDecimals={false} tick={{ fill: "var(--color-subtle)", fontSize: 12 }} axisLine={false} tickLine={false} width={28} />
                <Tooltip cursor={{ fill: "var(--color-paper-3)" }} contentStyle={{ background: "var(--color-paper-3)", border: "none", borderRadius: 8, color: "var(--color-ink)" }} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {chartData.map((d) => (
                    <rect key={d.severity} fill={`var(--color-${severityHue(d.severity)})`} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <table className="sr-only">
            <caption>Findings by severity</caption>
            <tbody>
              {chartData.map((d) => (
                <tr key={d.severity}><th scope="row">{d.severity}</th><td>{d.count}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="card p-5">
          <h2 className="text-sm font-medium uppercase tracking-wider text-subtle">Executive summary</h2>
          <p className="mt-3 whitespace-pre-line text-sm leading-relaxed text-subtle">{data.summary}</p>
        </div>
      </div>
      <div>
        <h2 className="mb-3 text-sm font-medium uppercase tracking-wider text-subtle">Fix these first</h2>
        <div className="space-y-2">
          {top.map((f) => (
            <div key={f.rule_id + f.session_id} className="card flex flex-wrap items-center gap-3 px-4 py-3">
              <SeverityBadge sev={f.severity} />
              <span className="font-medium">{f.title}</span>
              <span className="font-mono text-xs text-faint">{f.session_id}</span>
              <span className="ml-auto text-xs text-subtle">{f.reference}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/** Findings grouped by standard + clause (differentiator #6). */
function ComplianceView({ findings }: { findings: Finding[] }) {
  const groups = new Map<string, Finding[]>();
  for (const f of findings) {
    const ref = f.reference || "Unmapped";
    const standard = ref.split(";")[0].split("§")[0].split(" (")[0].trim();
    const key = standard || ref;
    groups.set(key, [...(groups.get(key) ?? []), f]);
  }
  if (!findings.length) {
    return <EmptyState message="No findings — nothing to map. Every control the rules check passed." />;
  }
  return (
    <div className="space-y-5">
      <p className="text-[14px] leading-[1.4] text-subtle">
        Every finding is mapped to the standard it violates — NIST SP
        800-52r2, RFC 8996/8314/7465, BSI TR-02102, CERT-In advisories and
        the FIPS 203/204/205 post-quantum standards. Use this view to answer
        &quot;which control failed?&quot; per audit clause.
      </p>
      {[...groups.entries()].map(([standard, items]) => (
        <section key={standard} aria-label={standard}>
          <div className="mb-2 flex items-center gap-3">
            <h2 className="font-mono text-[13px] font-medium text-accent">{standard}</h2>
            <span className="label">{items.length} finding{items.length > 1 ? "s" : ""}</span>
          </div>
          <div className="card overflow-x-clip">
            <table className="w-full min-w-[640px] text-sm">
              <thead>
                <tr className="border-b border-line text-left text-xs uppercase tracking-wider text-subtle">
                  <th className="px-4 py-3 font-medium">Clause</th>
                  <th className="px-4 py-3 font-medium">Rule</th>
                  <th className="px-4 py-3 font-medium">Control</th>
                  <th className="px-4 py-3 font-medium">Result</th>
                  <th className="px-4 py-3 font-medium">Sessions</th>
                </tr>
              </thead>
              <tbody>
                {items.map((f) => {
                  const clause = f.reference.split(";")[0].trim();
                  return (
                    <tr key={f.rule_id + f.session_id} className="border-b border-line last:border-0">
                      <td className="px-4 py-2.5 font-mono text-xs">{clause}</td>
                      <td className="px-4 py-2.5 font-mono text-xs text-subtle">{f.rule_id}</td>
                      <td className="px-4 py-2.5">{f.title}</td>
                      <td className="px-4 py-2.5">
                        <span className="inline-flex items-center gap-1.5">
                          <SeverityBadge sev={f.severity} />
                          <span className="text-[12px] text-faint">fail</span>
                        </span>
                      </td>
                      <td className="px-4 py-2.5 font-mono text-xs text-subtle">
                        {f.session_id ?? "host-level"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      ))}
    </div>
  );
}

function SessionsTable({ scanId, sessions }: { scanId: string; sessions: Session[] }) {
  const [filter, setFilter] = useState("");
  const shown = filter
    ? sessions.filter((s) => s.transport === filter)
    : sessions;
  return (
    <div className="space-y-3">
      <div className="flex gap-2" role="group" aria-label="Filter by transport">
        {["", "implicit", "starttls", "plaintext"].map((t) => (
          <button
            key={t || "all"}
            onClick={() => setFilter(t)}
            className={`rounded-[4px] px-3 py-1.5 font-mono text-[13px] font-medium transition-colors ${
              filter === t ? "text-white" : "text-subtle hover:text-ink"
            }`}
            style={filter === t ? { background: "var(--color-primary)" } : undefined}
          >
            {t || "all"}
          </button>
        ))}
      </div>
      <div className="card overflow-x-clip">
        <table className="w-full min-w-[860px] text-sm">
          <thead>
            <tr className="border-b border-line text-left text-xs uppercase tracking-wider text-subtle">
              <th className="px-4 py-3 font-medium">Session</th>
              <th className="px-4 py-3 font-medium">Proto</th>
              <th className="px-4 py-3 font-medium">Server</th>
              <th className="px-4 py-3 font-medium">TLS</th>
              <th className="px-4 py-3 font-medium">Cipher</th>
              <th className="px-4 py-3 font-medium">PFS</th>
              <th className="px-4 py-3 font-medium">ML</th>
              <th className="px-4 py-3 font-medium">Grade</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((s) => (
              <tr key={s.session_id} className="border-b border-line last:border-0">
                <td className="px-4 py-2.5">
                  <Link href={`/scans/${scanId}/sessions/${s.session_id}`} className="font-mono text-xs text-accent hover:underline">
                    {s.session_id}
                  </Link>
                  {s.is_anomaly && <Warning size={13} weight="fill" className="ml-2 inline align-[-2px] text-medium" aria-label="anomalous session" />}
                  {s.reassembly_incomplete && (
                    <span title="TCP reassembly hit a gap; stream truncated at the hole" aria-label="reassembly incomplete"
                      className="ml-2 font-mono text-[11px]" style={{ color: "var(--color-medium)" }}>
                      ⚐gap
                    </span>
                  )}
                </td>
                <td className="px-4 py-2.5"><ProtoTag proto={s.protocol} /></td>
                <td className="px-4 py-2.5 font-mono text-xs">{s.server_host || `${s.dst_ip}:${s.dst_port}`}</td>
                <td className="px-4 py-2.5">{s.tls_version || <span className="text-critical">none</span>}</td>
                <td className="max-w-56 truncate px-4 py-2.5 font-mono text-xs">{s.cipher_suite || "—"}</td>
                <td className="px-4 py-2.5">{s.pfs === null ? "—" : s.pfs ? "✓" : <span className="text-medium">✗</span>}</td>
                <td className="px-4 py-2.5">
                  {s.ml_risk ? (
                    <span className="inline-flex items-center gap-1.5">
                      <span
                        className="rounded-[3px] px-1.5 py-0.5 font-mono text-[11.5px]"
                        style={{
                          background: s.ml_risk.label === "low" ? "var(--color-pass-bg)" :
                                      s.ml_risk.label === "medium" ? "var(--color-low-bg)" : "var(--color-medium-bg)",
                          color: s.ml_risk.label === "low" ? "var(--color-pass)" :
                                 s.ml_risk.label === "medium" ? "var(--color-low)" : "var(--color-medium)",
                        }}
                      >
                        {s.ml_risk.label}
                      </span>
                      {s.is_anomaly && (
                        <span className="font-mono text-[11px]" style={{ color: "var(--color-medium)" }} title="IsolationForest anomaly">
                          z-flag
                        </span>
                      )}
                    </span>
                  ) : "—"}
                </td>
                <td className="px-4 py-2.5"><GradeChip grade={s.grade} score={s.risk_score} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function FindingsList({ findings }: { findings: Finding[] }) {
  const [open, setOpen] = useState<string | null>(null);
  const grouped = SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s)] as const)
    .filter(([, items]) => items.length > 0);
  return (
    <div className="space-y-8">
      {grouped.length === 0 && <EmptyState message="No findings — every session passed every rule." />}
      {grouped.map(([sev, items]) => (
        <section key={sev} aria-label={`${sev} findings`}>
          <div className="mb-3 flex items-center gap-3">
            <SeverityBadge sev={sev} />
            <h2 className="text-sm text-subtle">{items.length} finding{items.length > 1 ? "s" : ""}</h2>
          </div>
          <div className="space-y-2">
            {items.map((f) => {
              const key = `${f.rule_id}-${f.session_id}`;
              return (
                <div key={key} className="card px-4 py-3">
                  <button className="flex w-full flex-wrap items-center gap-3 text-left" onClick={() => setOpen(open === key ? null : key)} aria-expanded={open === key}>
                    <span className="font-medium">{f.title}</span>
                    <span className="font-mono text-xs text-faint">{f.rule_id}{f.session_id ? " · " + f.session_id : " · host-level"}</span>
                    <span className="ml-auto text-xs text-subtle">{f.reference}</span>
                  </button>
                  <p className="mt-1.5 text-sm text-subtle">{f.description}</p>
                  {open === key && (
                    <div className="mt-3 space-y-3 border-t border-line pt-3 text-[14px]">
                      <p><span className="text-subtle">Fix: </span>{f.remediation}</p>
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="label">evidence</span>
                        <code className="rounded-[4px] bg-raised px-2 py-0.5 font-mono text-[12.5px] text-subtle">{JSON.stringify(f.evidence)}</code>
                      </div>
                      {f.evidence_frames && f.evidence_frames.length > 0 && (
                        <EvidenceFrames frames={f.evidence_frames} />
                      )}
                      {f.evidence_hex && (
                        <div className="space-y-1.5">
                          <span className="label">raw bytes (capture window)</span>
                          <EvidenceHex hex={f.evidence_hex} />
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </section>
      ))}
    </div>
  );
}

function CertsList({ certs }: { certs: Certificate[] }) {
  if (certs.length === 0) return <EmptyState message="No certificates were exchanged in this capture." />;
  return (
    <div className="grid gap-4 md:grid-cols-2">
      {certs.map((c) => {
        const total = Math.max(1, c.days_to_expiry);
        return (
          <div key={c.fingerprint_sha256} className="card p-5">
            <div className="flex items-start justify-between gap-3">
              <div>
                <h3 className="font-medium">{c.subject_cn}</h3>
                <p className="text-xs text-subtle">issued by {c.issuer_cn}</p>
              </div>
              {c.is_expired ? <SeverityBadge sev="critical" /> : c.self_signed ? <SeverityBadge sev="high" /> : <SeverityBadge sev="low" />}
            </div>
            <div className="mt-4 space-y-1.5 text-sm">
              <div className="flex justify-between text-subtle"><span>Key</span><span>{c.key_algorithm} {c.key_length} bit</span></div>
              <div className="flex justify-between text-subtle"><span>Signature</span><span>{c.signature_hash}</span></div>
              <div className="flex justify-between text-subtle"><span>Valid until</span><span className={c.is_expired ? "text-critical" : ""}>{c.not_after.slice(0, 10)}{c.is_expired ? " (expired)" : ""}</span></div>
            </div>
            <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-raised" aria-hidden>
              <div className="h-full rounded-full" style={{ width: `${Math.min(100, (c.days_to_expiry / 396) * 100)}%`, background: c.is_expired ? "var(--color-critical)" : "var(--color-pass)" }} />
            </div>
            {c.chain_issues.length > 0 && (
              <ul className="mt-3 space-y-1 text-xs text-medium">
                {c.chain_issues.map((i) => <li key={i}>· {i}</li>)}
              </ul>
            )}
            <div className="mt-3 flex items-center gap-2 font-mono text-xs text-faint">
              <span className="truncate">{c.fingerprint_sha256.slice(0, 28)}…</span>
              <CopyButton text={c.fingerprint_sha256} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function AnomaliesList({ anomalies }: { anomalies: (Session & { explanation: { top_features: { feature: string; value: number; z: number }[] } })[] }) {
  if (anomalies.length === 0) return <EmptyState message="No anomalous TLS sessions — traffic matches the healthy baseline." />;
  return (
    <div className="space-y-3">
      {anomalies.map((a) => (
        <div key={a.session_id} className="card p-5">
          <div className="flex flex-wrap items-center gap-3">
            <SeverityBadge sev={severityHue(a.grade)} />
            <span className="font-mono text-sm">{a.session_id}</span>
            <span className="text-sm text-subtle">{a.protocol} · {a.tls_version || "no TLS"} · grade {a.grade}</span>
            <span className="ml-auto tabular font-mono text-xs text-faint">score {a.anomaly_score.toFixed(3)}</span>
          </div>
          {a.explanation?.top_features && (
            <p className="mt-3 text-sm text-subtle">
              Deviates from the healthy baseline:{" "}
              {a.explanation.top_features.map((t) => `${t.feature.replace(/_/g, " ")} (${t.z > 0 ? "+" : ""}${t.z}σ)`).join(", ")}.
            </p>
          )}
        </div>
      ))}
    </div>
  );
}

function Reports({ scanId }: { scanId: string }) {
  const { toast } = useToasts();
  const [busy, setBusy] = useState<string | null>(null);
  const items: [string, "json" | "html" | "pdf", string][] = [
    ["JSON", "json", "Complete forensic export — every session, finding, certificate and feature."],
    ["HTML", "html", "Self-contained report, opens in any browser."],
    ["PDF", "pdf", "Print-ready assessment with findings, inventories and compliance references."],
  ];
  async function grab(format: "json" | "html" | "pdf") {
    setBusy(format);
    try {
      await downloadReport(scanId, format);
      toast(
        format === "html" ? "Report opened in a new tab." : "Report downloaded.",
        "success",
      );
    } catch (err) {
      toast(err instanceof Error ? err.message : "Download failed", "error");
    } finally {
      setBusy(null);
    }
  }
  return (
    <div className="grid gap-4 md:grid-cols-3">
      {items.map(([name, format, desc]) => (
        <button
          key={name}
          type="button"
          onClick={() => grab(format)}
          disabled={busy !== null}
          aria-label={`Download ${name} report`}
          className="card group flex cursor-pointer flex-col gap-2 p-5 text-left transition-colors hover:bg-raised disabled:opacity-60"
        >
          <div className="flex items-center justify-between">
            <span className="font-mono text-sm font-semibold text-accent">
              {busy === format ? "Preparing…" : name}
            </span>
            <DownloadSimple size={17} className="text-subtle group-hover:text-ink" aria-hidden />
          </div>
          <p className="text-sm text-subtle">{desc}</p>
        </button>
      ))}
    </div>
  );
}
