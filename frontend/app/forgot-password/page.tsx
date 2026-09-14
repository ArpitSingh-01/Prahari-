"use client";

import Link from "next/link";
import { useState } from "react";
import { motion, useReducedMotion } from "motion/react";
import { SUPABASE_CONFIGURED } from "@/lib/api";
import { ErrorNote } from "@/components/ui";

const EASE = [0.32, 0.72, 0, 1] as const;

export default function ForgotPasswordPage() {
  const reduce = useReducedMotion();
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState("");

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      if (!SUPABASE_CONFIGURED) {
        throw new Error(
          "Password reset needs a configured auth service. In local/demo " +
            "mode just sign in again with any email — sessions are local.",
        );
      }
      const { getBrowserClient } = await import("@/lib/supabase");
      const { error: sbError } =
        await getBrowserClient().auth.resetPasswordForEmail(email, {
          redirectTo: `${location.origin}/auth/callback?next=/reset-password`,
        });
      if (sbError) throw new Error(sbError.message);
      setSent(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Request failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="theme-light relative flex min-h-dvh items-center justify-center overflow-hidden px-5">
      <motion.div
        className="card w-full max-w-sm border border-line p-8"
        initial={reduce ? { opacity: 0 } : { opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: reduce ? 0.15 : 0.5, ease: EASE }}
      >
        <Link href="/login" className="flex items-center gap-2 text-ink">
          <span className="brand-edge h-3.5 w-3.5 rounded-[3px]" aria-hidden />
          <span className="text-[14px] font-medium tracking-tight">Prahari</span>
        </Link>
        {sent ? (
          <>
            <h1 className="mt-6 text-2xl font-medium tracking-tight text-ink">
              Check your email
            </h1>
            <p className="mt-2 text-[14px] leading-[1.4] text-subtle">
              If <b>{email}</b> belongs to an account, a reset link is on its
              way. It expires in an hour.
            </p>
          </>
        ) : (
          <>
            <h1 className="mt-6 text-2xl font-medium tracking-tight text-ink">
              Reset your password
            </h1>
            <p className="mt-2 text-[14px] leading-[1.25] text-subtle">
              We&apos;ll email you a one-time reset link.
            </p>
            <form onSubmit={submit} className="mt-7 space-y-4">
              <label className="block">
                <span className="label mb-1.5 block">email</span>
                <input
                  type="email"
                  required
                  autoComplete="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@corp.example"
                  className="w-full rounded-[4px] border border-line bg-white px-3 py-2.5 text-[15px] text-ink placeholder:text-faint focus:border-[#0000ee] focus:outline-none"
                />
              </label>
              {error && <ErrorNote message={error} />}
              <button type="submit" disabled={busy} className="btn btn-primary w-full">
                {busy ? "Sending…" : "Send reset link"}
              </button>
            </form>
          </>
        )}
        <p className="mt-5 text-center text-[13px] text-subtle">
          <Link href="/login" className="underline underline-offset-2">
            Back to sign in
          </Link>
        </p>
      </motion.div>
    </main>
  );
}
