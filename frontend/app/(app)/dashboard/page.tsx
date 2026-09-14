"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { ArrowRight, ArrowUpRight } from "@phosphor-icons/react/dist/ssr";
import { api } from "@/lib/api";
import type { Scan } from "@/lib/types";
import { bytes } from "@/lib/visuals";
import { GradeChip } from "@/components/ui";
import { PostureTrend } from "@/components/PostureTrend";
import { EmptyState, ErrorNote, StatCard } from "@/components/ui";

export default function Dashboard() {
  const { data, error, isLoading } = useQuery({
    queryKey: ["scans"],
    queryFn: () => api<{ items: Scan[]; total: number }>("/api/scans?limit=50"),
    refetchInterval: (q) =>
      q.state.data?.items.some((s) => s.status === "parsing") ? 2000 : false,
  });

  const scans = data?.items ?? [];
  const complete = scans.filter((s) => s.status === "complete");
  const avg = complete.length
    ? Math.round(complete.reduce((a, s) => a + (s.posture_score ?? 0), 0) / complete.length)
    : null;
  const worst = complete.reduce<Scan | null>(
    (w, s) => (!w || (s.posture_score ?? 100) < (w.posture_score ?? 100) ? s : w),
    null,
  );

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="label mb-2">console</p>
          <h1 className="text-3xl font-medium leading-[1.13] tracking-tight">Dashboard</h1>
        </div>
        <Link
          href="/scans/new"
          className="group flex items-center gap-2 rounded-[4px] px-4 py-2.5 text-[14px] font-medium text-white transition-transform duration-200 hover:-translate-y-px"
          style={{ background: "var(--color-primary)" }}
        >
          New scan
          <ArrowRight size={15} weight="bold" className="transition-transform duration-200 group-hover:translate-x-0.5" aria-hidden />
        </Link>
      </header>

      {error && <ErrorNote message={(error as Error).message} />}

      {complete.length >= 2 && (
        <div className="card p-5">
          <h2 className="label mb-4">posture trend</h2>
          <PostureTrend
            points={complete
              .slice()
              .sort((a, b) => +new Date(a.created_at) - +new Date(b.created_at))
              .map((sc) => ({
                name: sc.name,
                date: new Date(sc.created_at).toLocaleDateString(),
                score: sc.posture_score ?? 0,
              }))}
          />
        </div>
      )}

      {complete.length > 0 && (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <StatCard label="scans" value={complete.length} />
          <StatCard label="avg posture" value={avg ?? "—"} delta="completed scans" />
          <StatCard
            label="weakest"
            value={worst ? `${worst.posture_score}/100` : "—"}
            delta={worst?.name ?? ""}
          />
          <StatCard
            label="sessions analyzed"
            value={complete.reduce((a, s) => a + (s.session_count ?? 0), 0)}
          />
        </div>
      )}

      {isLoading ? (
        <div className="card h-40 animate-pulse" />
      ) : scans.length === 0 ? (
        <EmptyState
          message="No captures yet. Upload a PCAP of your mail traffic, SMTP, IMAP or POP3, encrypted or not, and the engine reconstructs every session."
          action={
            <Link
              href="/scans/new"
              className="rounded-[4px] px-5 py-2.5 text-[14px] font-medium text-white"
              style={{ background: "var(--color-primary)" }}
            >
              Upload your first capture
            </Link>
          }
        />
      ) : (
        <div className="card overflow-x-clip">
          <table className="w-full text-[14px]">
            <thead>
              <tr className="border-b border-white/[0.07] text-left">
                <th className="label px-4 py-3">capture</th>
                <th className="label px-4 py-3">status</th>
                <th className="label hidden px-4 py-3 sm:table-cell">sessions</th>
                <th className="label hidden px-4 py-3 md:table-cell">size</th>
                <th className="label px-4 py-3">posture</th>
                <th className="px-4 py-3" aria-label="Open" />
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => (
                <tr key={s.id} className="border-b border-white/[0.05] transition-colors last:border-0 hover:bg-raised/60">
                  <td className="px-4 py-3">
                    <Link href={`/scans/${s.id}`} className="font-medium hover:text-link">
                      {s.name}
                    </Link>
                    <div className="label mt-0.5">
                      {new Date(s.created_at).toLocaleString()}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-subtle">
                    {s.status === "complete" ? (
                      "complete"
                    ) : s.status === "failed" ? (
                      <span className="text-critical">failed</span>
                    ) : (
                      <span className="pulsing" style={{ color: "var(--color-accent)" }}>
                        {s.progress}%
                      </span>
                    )}
                  </td>
                  <td className="tabular hidden px-4 py-3 sm:table-cell">
                    {s.session_count ?? "—"}
                  </td>
                  <td className="tabular hidden px-4 py-3 text-subtle md:table-cell">
                    {bytes(s.file_size)}
                  </td>
                  <td className="px-4 py-3">
                    {s.grade ? (
                      <GradeChip grade={s.grade} score={s.posture_score ?? undefined} />
                    ) : (
                      "—"
                    )}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <Link
                      href={`/scans/${s.id}`}
                      className="inline-flex text-link hover:underline"
                      aria-label={`Open ${s.name}`}
                    >
                      <ArrowUpRight size={16} aria-hidden />
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
