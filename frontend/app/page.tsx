"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { motion, useReducedMotion } from "motion/react";
import { ArrowRight, ArrowUpRight } from "@phosphor-icons/react/dist/ssr";
import { FadeUp, RevealOnScroll } from "@/components/motion";
import { isLoggedIn, api } from "@/lib/api";
import { useQuery } from "@tanstack/react-query";

const EASE = [0.32, 0.72, 0, 1] as const;

const FINDINGS = [
  { sev: "critical", text: "TLS 1.0 negotiated on smtp-old:465", ref: "NIST 800-52r2" },
  { sev: "critical", text: "RC4 suite accepted by mail-gw", ref: "RFC 7465" },
  { sev: "high", text: "Certificate expired 14d ago (imap.corp)", ref: "CA/B BR" },
  { sev: "high", text: "STARTTLS stripped on port 25", ref: "RFC 8314" },
  { sev: "medium", text: "RSA kex — no forward secrecy", ref: "NIST 800-52r2" },
];

/* severity hues tuned for the light marketing canvas (AA on #ffffff) */
const SEV: Record<string, string> = {
  critical: "#c93400",
  high: "#a05f00",
  medium: "#7a6a00",
};

const STAGES = [
  ["Ingest", "pcap / pcapng, any link layer"],
  ["Identify", "SMTP, IMAP, POP3 by payload"],
  ["Reassemble", "TCP streams, retransmits deduped"],
  ["Detect", "STARTTLS upgrades + strips"],
  ["Parse", "handshakes, offered vs chosen ciphers"],
  ["Verify", "X.509 chains, keys, expiry, SNI"],
  ["Judge", "25 rules mapped to NIST + CERT-In"],
  ["Learn", "ML risk class + anomaly z-scores"],
  ["Score", "0-100 posture, A-F grades"],
  ["Report", "JSON, HTML, PDF"],
];

const COLUMNS: [string, string][] = [
  ["Reads the real wire", "Not your config files. The capture shows what actually negotiated, what actually decrypted, what actually expired."],
  ["Explains itself", "Every finding names its rule, its NIST or CERT-In reference, its evidence bytes, and the one-line fix. No black boxes."],
  ["ML you can defend", "The classifier learns rule-derived labels; the Isolation Forest flags sessions that deviate from your healthy baseline and says which features and by how much."],
  ["Passive forever", "Nothing is sent to your servers. No probes, no logins, no keys. The mail keeps flowing while you look."],
];

function Ticker() {
  const reduce = useReducedMotion();
  const [idx, setIdx] = useState(0);
  useEffect(() => {
    if (reduce) return;
    const t = setInterval(() => setIdx((i) => (i + 1) % FINDINGS.length), 2400);
    return () => clearInterval(t);
  }, [reduce]);

  return (
    <div className="card border-line p-6" aria-label="Example findings feed">
      <div className="mb-4 flex items-center justify-between">
        <span className="label">findings feed</span>
        <span className="flex items-center gap-1.5">
          <span
            className="pulsing h-1.5 w-1.5 rounded-full"
            style={{ background: "#157f3d" }}
            aria-hidden
          />
          <span className="label">live</span>
        </span>
      </div>
      <ul className="space-y-3">
        {FINDINGS.map((f, i) => (
          <motion.li
            key={f.text}
            className="flex items-center gap-3 text-[15px] leading-[1.25] text-ink"
            initial={false}
            animate={{
              opacity: i === idx ? 1 : 0.32,
              x: reduce ? 0 : i === idx ? 4 : 0,
            }}
            transition={{ duration: 0.4, ease: EASE }}
          >
            <span
              className="h-1.5 w-1.5 shrink-0 rounded-full"
              style={{ background: SEV[f.sev] }}
              aria-label={`${f.sev} finding`}
            />
            <span className="min-w-0 flex-1">{f.text}</span>
            <span className="label shrink-0">{f.ref}</span>
          </motion.li>
        ))}
      </ul>
      <div className="mt-5 flex items-center justify-between border-t border-line pt-4">
        <span className="label">posture</span>
        <span className="tabular text-2xl font-medium" style={{ color: SEV.critical }}>
          52<span className="text-base text-subtle"> / 100 · F</span>
        </span>
      </div>
    </div>
  );
}

function LiveStats() {
  const { data } = useQuery({
    queryKey: ["public-stats"],
    queryFn: () => api<{ scans: number; sessions: number; findings: number }>
      ("/api/stats"),
    // real numbers only; the endpoint reports null-equivalents until scans exist
  });
  const items: [string, string | number | null][] = [
    ["captures analyzed", data?.scans || null],
    ["sessions reconstructed", data?.sessions || null],
    ["findings raised", data?.findings || null],
  ];
  return (
    <div
      className="grid grid-cols-3 gap-px overflow-hidden rounded-[12px] border border-line bg-line"
      aria-label="Live deployment counters"
    >
      {items.map(([label, value]) => (
        <div key={label} className="bg-white p-5 text-center">
          <div
            className="tabular text-3xl font-medium leading-none text-ink"
            aria-label={label}
          >
            {value ?? "—"}
          </div>
          <div className="label mt-2">{label}</div>
        </div>
      ))}
    </div>
  );
}

export default function Landing() {
  // localStorage is browser-only; read AFTER mount so SSR and first client
  // render match (no hydration mismatch)
  const [signed, setSigned] = useState(false);
  useEffect(() => {
    setSigned(isLoggedIn());
  }, []);
  const consoleHref = signed ? "/dashboard" : "/login";

  return (
    <div className="theme-light min-h-dvh">
      {/* nav — fixed, 64px, 1440px max (per extraction) */}
      <header className="fixed inset-x-0 top-0 z-40 bg-white/90 backdrop-blur-md">
        <div className="mx-auto flex h-16 max-w-[1440px] items-center justify-between px-8">
          <Link href="/" className="flex items-center gap-2 text-ink">
            <span className="brand-edge h-3.5 w-3.5 rounded-[3px]" aria-hidden />
            <span className="text-[15px] font-medium tracking-tight">Prahari</span>
          </Link>
          <nav className="flex items-center gap-6 text-[14px]" aria-label="Main">
            <a href="#pipeline" className="hidden text-subtle transition-colors hover:text-ink sm:block">
              Pipeline
            </a>
            <a href="#capabilities" className="hidden text-subtle transition-colors hover:text-ink sm:block">
              Capabilities
            </a>
            <Link href={consoleHref} className="btn btn-primary h-9 text-[13px]">
              Console
              <ArrowUpRight size={14} aria-hidden />
            </Link>
          </nav>
        </div>
      </header>

      {/* hero — h1 72/81 per extraction; split with live feed */}
      <section className="pt-16">
        <div className="mx-auto grid max-w-[1440px] gap-12 px-8 pb-16 pt-14 sm:pt-20 lg:grid-cols-[1.15fr_0.85fr] lg:items-center">
          <div>
            <FadeUp>
              <p className="label mb-4">passive pcap forensics · SMTP IMAP POP3</p>
            </FadeUp>
            <FadeUp delay={0.06}>
              <h1 className="max-w-[760px] text-[44px] font-medium leading-[1.08] tracking-[-0.03em] text-ink sm:text-[56px] lg:text-[72px] lg:leading-[81px]">
                What your email crypto really looks like,
                <span className="grad-text"> on the wire.</span>
              </h1>
            </FadeUp>
            <FadeUp delay={0.14}>
              <p className="mt-5 max-w-[460px] text-[17px] leading-[1.3] text-subtle">
                Upload a capture. Every handshake parsed, every certificate
                checked, every weakness scored with its fix.
              </p>
            </FadeUp>
            <FadeUp delay={0.22}>
              <div className="mt-8 flex flex-wrap items-center gap-3">
                <Link href={signed ? "/scans/new" : "/login"} className="btn btn-primary">
                  Analyze a capture
                  <ArrowRight size={15} weight="bold" aria-hidden />
                </Link>
                <a href="#pipeline" className="btn btn-ghost">
                  See the pipeline
                </a>
              </div>
            </FadeUp>
          </div>
          <FadeUp delay={0.2}>
            <Ticker />
          </FadeUp>
        </div>
      </section>

      {/* live counters from the deployed engine — real numbers only */}
      <section className="mx-auto max-w-[1440px] px-8 pb-16">
        <RevealOnScroll>
          <LiveStats />
        </RevealOnScroll>
      </section>

      {/* pipeline */}
      <section id="pipeline" className="border-t border-line bg-surface">
        <div className="mx-auto max-w-[1440px] px-8 py-16">
          <RevealOnScroll>
            <p className="label mb-3">the pipeline</p>
            <h2 className="max-w-xl text-[32px] font-medium leading-[1.15] tracking-[-0.02em] text-ink sm:text-[40px]">
              Ten stages. One verdict.
            </h2>
          </RevealOnScroll>
          <div className="mt-10 grid gap-px overflow-hidden rounded-[12px] border border-line bg-line sm:grid-cols-2 lg:grid-cols-5">
            {STAGES.map(([name, detail], i) => (
              <RevealOnScroll key={name} delay={i * 0.03} className="bg-white">
                <div className="group h-full p-5 transition-colors duration-200 hover:bg-surface">
                  <span className="label">{String(i + 1).padStart(2, "0")}</span>
                  <p className="mt-3 text-[17px] font-medium leading-tight text-ink">{name}</p>
                  <p className="mt-1.5 text-[14px] leading-[1.25] text-subtle">{detail}</p>
                </div>
              </RevealOnScroll>
            ))}
          </div>
        </div>
      </section>

      {/* capabilities */}
      <section id="capabilities" className="border-t border-line">
        <div className="mx-auto max-w-[1440px] px-8 py-16">
          <RevealOnScroll>
            <p className="label mb-3">capabilities</p>
            <h2 className="max-w-xl text-[32px] font-medium leading-[1.15] tracking-[-0.02em] text-ink sm:text-[40px]">
              Built for people who answer 3 a.m. pages.
            </h2>
          </RevealOnScroll>
          <div className="mt-10 grid gap-8 sm:grid-cols-2">
            {COLUMNS.map(([title, body], i) => (
              <RevealOnScroll key={title} delay={i * 0.05}>
                <div className="border-l-2 border-line pl-5 transition-colors duration-300 hover:border-[#6a2f8d]">
                  <h3 className="text-xl font-medium leading-[1.25] text-ink">{title}</h3>
                  <p className="mt-2.5 max-w-[46ch] text-[15px] leading-[1.25] text-subtle">{body}</p>
                </div>
              </RevealOnScroll>
            ))}
          </div>
        </div>
      </section>

      {/* CTA — violet full-bleed band (per extraction) */}
      <section className="mkt-band">
        <div className="mx-auto max-w-[1440px] px-8 py-16 text-center">
          <RevealOnScroll>
            <h2 className="mx-auto max-w-[560px] text-[32px] font-medium leading-[1.15] tracking-[-0.02em] sm:text-[40px]">
              The mail keeps flowing.
              <br />
              You just see it clearly.
            </h2>
            <Link
              href={consoleHref}
              className="btn mt-8 bg-white text-[#1d161d] hover:bg-[#f8f6f8]"
            >
              Open the console
              <ArrowRight size={16} weight="bold" aria-hidden />
            </Link>
          </RevealOnScroll>
        </div>
      </section>

      {/* footer — 1280px per extraction */}
      <footer className="border-t border-line">
        <div className="mx-auto flex max-w-[1280px] flex-wrap items-center justify-between gap-4 px-8 py-10">
          <span className="flex items-center gap-2 text-ink">
            <span className="brand-edge h-3 w-3 rounded-[3px]" aria-hidden />
            <span className="text-[14px] font-medium">Prahari</span>
          </span>
          <span className="label">SIH 2026 · PS 26159 · NTRO</span>
          <span className="label">NIST SP 800-52r2 · BSI · CERT-In</span>
        </div>
      </footer>
    </div>
  );
}
