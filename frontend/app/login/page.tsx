"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";
import { motion, useReducedMotion } from "motion/react";
import { ArrowRight, Eye, EyeSlash } from "@phosphor-icons/react/dist/ssr";
import { api, devLogin, supabaseLogout, SUPABASE_CONFIGURED } from "@/lib/api";
import { ErrorNote } from "@/components/ui";

const EASE = [0.32, 0.72, 0, 1] as const;

/** Map Supabase error messages to analyst-readable ones. */
function friendlyAuthError(msg: string): string {
  const m = msg.toLowerCase();
  if (m.includes("invalid login credentials"))
    return "Wrong email or password.";
  if (m.includes("email not confirmed"))
    return "Check your inbox first — this account's email isn't confirmed yet.";
  if (m.includes("rate limit") || m.includes("too many"))
    return "Too many attempts. Wait a minute and try again.";
  if (m.includes("failed to fetch") || m.includes("network"))
    return "Cannot reach the auth service. Check your connection and retry.";
  return msg;
}

function LoginForm() {
  const router = useRouter();
  const params = useSearchParams();
  const reduce = useReducedMotion();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");

  const next = params.get("next") || "/dashboard";

  // email-confirmation token flow (from /auth/confirm) and error redirects
  useEffect(() => {
    const err = params.get("error");
    if (err) setError(decodeURIComponent(err));
    const token = params.get("token");
    const type = params.get("type");
    if (token && SUPABASE_CONFIGURED) {
      (async () => {
        try {
          const { getBrowserClient } = await import("@/lib/supabase");
          const { error: vErr } =
            await getBrowserClient().auth.verifyOtp({
              token_hash: token,
              type: (type === "recovery" || type === "invite" ||
                     type === "email_change" || type === "signup")
                ? (type as "signup")
                : "signup",
            });
          if (vErr) setError(friendlyAuthError(vErr.message));
          else {
            setNotice("Email confirmed — you're signed in.");
            router.push(type === "recovery" ? "/reset-password" : "/dashboard");
          }
        } catch {
          setError("Could not verify the confirmation token — request a new one.");
        }
      })();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      if (SUPABASE_CONFIGURED) {
        const { getBrowserClient } = await import("@/lib/supabase");
        const { error: sbError } =
          await getBrowserClient().auth.signInWithPassword({ email, password });
        if (sbError) throw new Error(friendlyAuthError(sbError.message));
      } else {
        await devLogin(email);
      }
      router.push(next);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
      setBusy(false);
    }
  }

  async function demo() {
    setBusy(true);
    setError("");
    try {
      if (SUPABASE_CONFIGURED) await supabaseLogout();
      await devLogin("demo@prahari.local");
      router.push(next);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Demo sign-in failed");
      setBusy(false);
    }
  }

  return (
    <main className="theme-light relative flex min-h-dvh items-center justify-center overflow-hidden px-5">
      <motion.div
        className="card relative w-full max-w-sm border border-line p-8"
        initial={reduce ? { opacity: 0 } : { opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: reduce ? 0.15 : 0.5, ease: EASE }}
      >
        <Link href="/" className="flex items-center gap-2 text-ink">
          <span className="brand-edge h-3.5 w-3.5 rounded-[3px]" aria-hidden />
          <span className="text-[14px] font-medium tracking-tight">Prahari</span>
        </Link>
        <h1 className="mt-6 text-2xl font-medium leading-[1.13] tracking-tight text-ink">
          Sign in
        </h1>
        <p className="mt-2 text-[14px] leading-[1.25] text-subtle">
          Your analyst account for the console.
        </p>
        <form onSubmit={submit} className="mt-7 space-y-4">
          {notice && (
            <p className="rounded-[6px] px-4 py-3 text-[14px]" role="status"
               style={{ background: "var(--color-pass-bg)", color: "#0d5c36" }}>
              {notice}
            </p>
          )}
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
          <label className="block">
            <span className="label mb-1.5 block">password</span>
            <span className="relative block">
              <input
                type={showPw ? "text" : "password"}
                required
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full rounded-[4px] border border-line bg-white px-3 py-2.5 pr-10 text-[15px] text-ink placeholder:text-faint focus:border-[#0000ee] focus:outline-none"
              />
              <button
                type="button"
                onClick={() => setShowPw((v) => !v)}
                aria-label={showPw ? "Hide password" : "Show password"}
                className="absolute inset-y-0 right-0 flex items-center px-3 text-subtle transition-colors hover:text-ink"
              >
                {showPw ? <EyeSlash size={16} aria-hidden /> : <Eye size={16} aria-hidden />}
              </button>
            </span>
          </label>
          {error && <ErrorNote message={error} />}
          <button type="submit" disabled={busy} className="btn btn-primary group w-full">
            {busy ? "Signing in…" : "Sign in"}
            {!busy && (
              <ArrowRight size={15} weight="bold" className="transition-transform duration-200 group-hover:translate-x-0.5" aria-hidden />
            )}
          </button>
        </form>
        <button
          onClick={demo}
          disabled={busy}
          className="btn btn-ghost mt-3 w-full text-[14px]"
        >
          Continue as demo analyst
        </button>
        <p className="mt-3 text-center text-[12px] leading-[1.3] text-faint">
          Demo mode runs the full pipeline against your own backend with a
          local token — no account, data stays on your machine.
        </p>
        <p className="mt-5 text-center text-[13px] leading-[1.25] text-subtle">
          No account?{" "}
          <Link href="/signup" className="underline underline-offset-2">Create one</Link>
          {" · "}
          <Link href="/forgot-password" className="underline underline-offset-2">
            Forgot password
          </Link>
        </p>
      </motion.div>
    </main>
  );
}


export default function LoginPage() {
  return (
    <Suspense fallback={<main className="theme-light min-h-dvh" />}>
      <LoginForm />
    </Suspense>
  );
}
