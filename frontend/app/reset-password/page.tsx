"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { motion, useReducedMotion } from "motion/react";
import { Eye, EyeSlash } from "@phosphor-icons/react/dist/ssr";
import { ErrorNote } from "@/components/ui";

const EASE = [0.32, 0.72, 0, 1] as const;

export default function ResetPasswordPage() {
  const router = useRouter();
  const reduce = useReducedMotion();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (password !== confirm) {
      setError("Passwords do not match");
      return;
    }
    if (password.length < 8) {
      setError("Use at least 8 characters");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const { getBrowserClient } = await import("@/lib/supabase");
      const { error: sbError } =
        await getBrowserClient().auth.updateUser({ password });
      if (sbError) throw new Error(sbError.message);
      router.push("/dashboard");
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Reset failed — request a new link",
      );
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
        <Link href="/" className="flex items-center gap-2 text-ink">
          <span className="brand-edge h-3.5 w-3.5 rounded-[3px]" aria-hidden />
          <span className="text-[14px] font-medium tracking-tight">Prahari</span>
        </Link>
        <h1 className="mt-6 text-2xl font-medium tracking-tight text-ink">
          Choose a new password
        </h1>
        <p className="mt-2 text-[14px] leading-[1.25] text-subtle">
          You&apos;re signed in via the reset link — set the new password now.
        </p>
        <form onSubmit={submit} className="mt-7 space-y-4">
          <label className="block">
            <span className="label mb-1.5 block">new password</span>
            <span className="relative block">
              <input
                type={showPw ? "text" : "password"}
                required
                minLength={8}
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full rounded-[4px] border border-line bg-white px-3 py-2.5 pr-10 text-[15px] text-ink focus:border-[#0000ee] focus:outline-none"
              />
              <button
                type="button"
                onClick={() => setShowPw((v) => !v)}
                aria-label={showPw ? "Hide password" : "Show password"}
                className="absolute inset-y-0 right-0 flex items-center px-3 text-subtle hover:text-ink"
              >
                {showPw ? <EyeSlash size={16} aria-hidden /> : <Eye size={16} aria-hidden />}
              </button>
            </span>
          </label>
          <label className="block">
            <span className="label mb-1.5 block">confirm password</span>
            <input
              type={showPw ? "text" : "password"}
              required
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              className="w-full rounded-[4px] border border-line bg-white px-3 py-2.5 text-[15px] text-ink focus:border-[#0000ee] focus:outline-none"
            />
          </label>
          {error && <ErrorNote message={error} />}
          <button type="submit" disabled={busy} className="btn btn-primary w-full">
            {busy ? "Saving…" : "Save new password"}
          </button>
        </form>
      </motion.div>
    </main>
  );
}
