"use client";

import { useState } from "react";
import { CopyButton } from "@/components/ui";

/** Hex-dump evidence view of the exact bytes that triggered a finding. */
export function EvidenceHex({ hex }: { hex: string }) {
  const bytes = hex.match(/.{1,2}/g) ?? [];
  const rows: { off: number; slice: string[] }[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    rows.push({ off: i, slice: bytes.slice(i, i + 16) });
  }
  const ascii = (b: string) => {
    const n = parseInt(b, 16);
    return n >= 32 && n < 127 ? String.fromCharCode(n) : ".";
  };
  return (
    <div className="overflow-x-auto rounded-[6px] bg-paper p-3">
      <pre className="font-mono text-[12.5px] leading-[1.6] text-subtle">
        {rows.map((r) => (
          <div key={r.off}>
            <span className="text-faint">{r.off.toString(16).padStart(4, "0")}  </span>
            {r.slice.map((b, i) => (
              <span key={i} className="mr-[3px]">{b}</span>
            ))}
            <span className="ml-3 text-ink">{r.slice.map(ascii).join("")}</span>
          </div>
        ))}
      </pre>
    </div>
  );
}

/** Frame chips — pcap packet numbers that carried this session's evidence. */
export function EvidenceFrames({ frames }: { frames: number[] }) {
  if (!frames?.length) return null;
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      <span className="label">frames</span>
      {frames.map((f) => (
        <span key={f} className="tabular rounded-[3px] bg-raised px-1.5 py-0.5 font-mono text-[12.5px] text-subtle">
          {f}
        </span>
      ))}
    </div>
  );
}
