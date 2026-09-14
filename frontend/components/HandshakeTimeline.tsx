"use client";

import { motion, useReducedMotion } from "motion/react";

const EASE = [0.32, 0.72, 0, 1] as const;

const LABELS: Record<string, string> = {
  starttls_command: "STARTTLS",
  starttls_accepted: "upgrade accepted",
  client_hello: "ClientHello",
  server_hello: "ServerHello",
  certificate: "Certificate",
  server_key_exchange: "ServerKeyExchange",
  client_key_exchange: "ClientKeyExchange",
  ccs: "ChangeCipherSpec",
  alert: "alert",
};

/** Vertical wire-order timeline of one session's TLS negotiation. */
export function HandshakeTimeline({
  events,
}: {
  events: { kind: string; detail: Record<string, unknown> }[];
}) {
  const reduce = useReducedMotion();
  const items = events?.length ? events : [];
  return (
    <div className="relative pl-5">
      <span aria-hidden className="absolute left-[5px] top-1.5 bottom-1.5 w-px bg-line" />
      <ol className="space-y-2">
        {items.map((e, i) => {
          const isStarttls = e.kind.startsWith("starttls");
          const isAlert = e.kind === "alert";
          return (
            <motion.li
              key={i}
              className="relative flex flex-wrap items-baseline gap-2 text-[14px]"
              initial={reduce ? { opacity: 0 } : { opacity: 0, x: -6 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.3, delay: i * 0.03, ease: EASE }}
            >
              <span
                aria-hidden
                className="absolute -left-5 top-[7px] h-1.5 w-1.5 rounded-full"
                style={{
                  background: isStarttls
                    ? "var(--color-accent)"
                    : isAlert
                      ? "var(--color-critical)"
                      : "var(--color-rule)",
                }}
              />
              <span className={isAlert ? "text-critical" : ""}>
                {LABELS[e.kind] ?? e.kind}
              </span>
              {typeof e.detail?.version === "string" && e.detail.version && (
                <span className="font-mono text-[12.5px] text-subtle">{e.detail.version}</span>
              )}
              {typeof e.detail?.cipher === "string" && e.detail.cipher && (
                <span className="font-mono text-[12.5px] text-subtle">{e.detail.cipher}</span>
              )}
              {typeof e.detail?.desc === "string" && (
                <span className="font-mono text-[12.5px] text-critical">{e.detail.desc}</span>
              )}
              {isStarttls && (
                <span className="rounded-[3px] px-1.5 font-mono text-[11.5px]" style={{ background: "var(--color-primary)", color: "#fff" }}>
                  plaintext
                </span>
              )}
            </motion.li>
          );
        })}
      </ol>
    </div>
  );
}
