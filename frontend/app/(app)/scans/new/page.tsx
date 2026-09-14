"use client";

import { useRouter } from "next/navigation";
import { useRef, useState } from "react";
import { motion, useReducedMotion, AnimatePresence } from "motion/react";
import { FileArrowUp } from "@phosphor-icons/react/dist/ssr";
import { api } from "@/lib/api";
import type { Scan } from "@/lib/types";
import { bytes } from "@/lib/visuals";
import { ErrorNote } from "@/components/ui";

const EASE = [0.32, 0.72, 0, 1] as const;

const STAGES = [
  "Uploading capture",
  "Waking the analysis engine (if asleep)",
  "Reconstructing TCP streams",
  "Parsing TLS handshakes",
  "Checking certificates & scoring",
];

const MAX_BYTES = 25 * 1024 * 1024;   // mirrors MAX_PCAP_BYTES (backend/app/pipeline/ingest.py)

/** One queued upload and where it is in the pipeline. */
type Item = {
  file: File;
  status: "queued" | "uploading" | "analyzing" | "done" | "failed";
  error?: string;
  scanId?: string;
};

type Status = Item["status"];
const STATUS_LABEL: Record<Status, string> = {
  queued: "queued",
  uploading: "uploading",
  analyzing: "analyzing",
  done: "done",
  failed: "failed",
};
const STATUS_STYLE: Record<Status, string> = {
  queued: "text-faint",
  uploading: "text-accent",
  analyzing: "text-accent",
  done: "text-pass",
  failed: "text-fail",
};

export default function NewScan() {
  const router = useRouter();
  const reduce = useReducedMotion();
  const inputRef = useRef<HTMLInputElement>(null);
  const [drag, setDrag] = useState(false);
  const [items, setItems] = useState<Item[]>([]);
  const [error, setError] = useState("");
  const [running, setRunning] = useState(false);
  const [stage, setStage] = useState(-1);

  function pick(list: FileList | null | undefined) {
    setError("");
    const files = Array.from(list ?? []);
    if (!files.length) return;
    const accepted: Item[] = [];
    for (const f of files) {
      if (!/\.(pcap|pcapng)$/i.test(f.name)) {
        setError(`${f.name}: expected a .pcap or .pcapng capture file`);
        continue;
      }
      if (f.size > MAX_BYTES) {
        setError(`${f.name}: captures are limited to 25 MB on the free deployment`);
        continue;
      }
      accepted.push({ file: f, status: "queued" });
    }
    if (accepted.length) setItems((prev) => [...prev, ...accepted]);
  }

  function setStatus(idx: number, patch: Partial<Item>) {
    setItems((prev) => prev.map((it, i) => (i === idx ? { ...it, ...patch } : it)));
  }

  /** Upload files strictly one at a time: the analysis engine is a small
   *  worker pool on a memory-capped free-tier host — a parallel burst of
   *  uploads would compete for the same worker slots anyway, and sequential
   *  keeps progress per file honest. One failure never aborts the rest. */
  async function start() {
    if (!items.length || running) return;
    setError("");
    setRunning(true);
    let firstScanId: string | null = null;
    let anyDone = false;
    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      if (item.status === "done" || item.status === "failed") continue;
      setStage(0);
      try {
        setStatus(i, { status: "uploading", error: undefined });
        const form = new FormData();
        form.append("file", item.file);
        setStage(1);
        const scan = await api<Scan>("/api/scans", { method: "POST", body: form });
        firstScanId = firstScanId ?? scan.id;
        setStatus(i, { status: "analyzing", scanId: scan.id });
        setStage(2);
        await api(`/api/scans/${scan.id}/analyze`, { method: "POST" });
        setStage(4);
        setStatus(i, { status: "done" });
        anyDone = true;
      } catch (err) {
        const message = err instanceof Error ? err.message : "Upload failed";
        setStatus(i, {
          status: "failed",
          error: message.includes("waking up")
            ? `${message} The engine answers within a minute on the free tier — retry this file afterwards.`
            : message,
        });
      }
    }
    setStage(-1);
    setRunning(false);
    if (anyDone) router.push(`/scans/${firstScanId}`);
  }

  const pendingCount = items.filter((i) => i.status !== "done" && i.status !== "failed").length;

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <header>
        <p className="label mb-2">new scan</p>
        <h1 className="text-3xl font-medium leading-[1.13] tracking-tight">
          Upload captures
        </h1>
        <p className="mt-2 text-[15px] leading-[1.25] text-subtle">
          Analysis is passive. Nothing touches your mail servers. Drop one or
          more files — they are analyzed one at a time.
        </p>
      </header>

      <motion.div
        role="button"
        tabIndex={0}
        aria-label="Choose pcap files"
        onClick={() => inputRef.current?.click()}
        onKeyDown={(e) => e.key === "Enter" && inputRef.current?.click()}
        onDragOver={(e) => {
          e.preventDefault();
          setDrag(true);
        }}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDrag(false);
          pick(e.dataTransfer.files);
        }}
        animate={drag && !reduce ? { scale: 1.01 } : { scale: 1 }}
        transition={{ duration: 0.2, ease: EASE }}
        className="card flex cursor-pointer flex-col items-center gap-3 px-6 py-16 text-center"
        style={{ borderColor: drag ? "var(--color-accent)" : undefined }}
      >
        <FileArrowUp size={28} className="text-subtle" aria-hidden />
        {items.length ? (
          <>
            <p className="text-[15px] font-medium">
              {items.length} capture{items.length > 1 ? "s" : ""} queued
            </p>
            <p className="label">{bytes(items.reduce((n, i) => n + i.file.size, 0))} total · click to add more</p>
          </>
        ) : (
          <>
            <p className="text-[15px] font-medium">Drop your .pcap files here</p>
            <p className="label">or click to browse · max 25 MB each</p>
          </>
        )}
        <input
          ref={inputRef}
          type="file"
          accept=".pcap,.pcapng"
          multiple
          className="sr-only"
          onChange={(e) => {
            pick(e.target.files);
            e.target.value = "";   // allow re-picking the same file later
          }}
        />
      </motion.div>

      {error && <ErrorNote message={error} />}

      <AnimatePresence>
        {items.length > 0 && (
          <motion.ol
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.3, ease: EASE }}
            className="card divide-y divide-line"
            aria-live="polite"
          >
            {items.map((item, i) => (
              <li key={`${item.file.name}-${i}`} className="flex items-center gap-3 px-4 py-3">
                <span className={`label min-w-[4.5rem] ${STATUS_STYLE[item.status]} ${
                  item.status === "uploading" || item.status === "analyzing" ? "pulsing" : ""
                }`}>
                  {STATUS_LABEL[item.status]}
                </span>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-[14px]">{item.file.name}</p>
                  <p className="label">{bytes(item.file.size)}</p>
                  {item.error && <p className="mt-1 text-[12px] leading-[1.4] text-fail">{item.error}</p>}
                </div>
                {item.status === "queued" && !running && (
                  <button
                    onClick={() => setItems((prev) => prev.filter((_, j) => j !== i))}
                    className="rounded-[4px] border border-line px-3 py-1 text-[12px] text-subtle transition-colors hover:border-subtle hover:text-ink"
                  >
                    Remove
                  </button>
                )}
              </li>
            ))}
          </motion.ol>
        )}
      </AnimatePresence>

      <AnimatePresence>
        {stage >= 0 && (
          <motion.ol
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.3, ease: EASE }}
            className="card space-y-2.5 p-5"
            aria-live="polite"
          >
            {STAGES.map((s, i) => (
              <li key={s} className="flex items-center gap-3 text-[14px]">
                {i < stage ? (
                  <span className="label" style={{ color: "var(--color-pass)" }}>done</span>
                ) : i === stage ? (
                  <span className="pulsing label" style={{ color: "var(--color-accent)" }}>
                    run
                  </span>
                ) : (
                  <span className="label">queued</span>
                )}
                <span className={i <= stage ? "" : "text-faint"}>{s}</span>
              </li>
            ))}
          </motion.ol>
        )}
      </AnimatePresence>

      <div className="flex justify-end gap-3">
        {items.length > 0 && !running && (
          <button
            onClick={() => setItems([])}
            className="rounded-[4px] border border-line px-5 py-2.5 text-[14px] text-subtle transition-colors hover:border-subtle hover:text-ink"
          >
            Clear
          </button>
        )}
        <button
          onClick={start}
          disabled={pendingCount === 0 || running}
          className="rounded-[4px] px-6 py-2.5 text-[14px] font-medium text-white transition-transform duration-200 hover:-translate-y-px disabled:opacity-50"
          style={{ background: "var(--color-primary)" }}
        >
          {running ? "Analyzing…" : `Run analysis${items.length > 1 ? ` (${pendingCount || items.length})` : ""}`}
        </button>
      </div>
    </div>
  );
}
