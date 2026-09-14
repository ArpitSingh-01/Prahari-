"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useMemo, useState } from "react";
import { motion, useReducedMotion } from "motion/react";
import { ArrowRight, Eye, EyeSlash } from "@phosphor-icons/react/dist/ssr";
import { devLogin, SUPABASE_CONFIGURED } from "@/lib/api";
import { ErrorNote } from "@/components/ui";

const EASE = [0.32, 0.72, 0, 1] as const;

type Strength = { score: number; label: string; hue: string };

function pwStrength(pw: string): Strength {
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
  if (/\d/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  const table: Strength[] = [
    { score: 0, label: "too weak", hue: "var(--color-critical)" },
    { score: 1, label: "weak", hue: "var(--color-critical)" },
    { score: 2, label: "fair", hue: "var(--color-medium)" },
    { score: 3, label: "good", hue: "var(--color-low)" },
    { score: 4, label: "strong", hue: "var(--color-pass)" },
    { score: 5, label: "excellent", hue: "var(--color-pass)" },
  ];
  return table[Math.min(score, pw ? 5 : 0)] ?? table[0];
}

export default function SignupPage() {
  const router = useRouter();
  const reduce = useReducedMotion();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [accepted, setAccepted] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  const strength = useMemo(() => pwStrength(password), [password]);

  const fieldError = ():
    | string
    | null =>
    confirm && password && confirm !== password ? "Passwords do not match" : null;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    if (password !== confirm) {
      setError("Passwords do not match");
      return;
    }
    if (!accepted) {
      setError("Please accept the usage terms (passive analysis of your own captures)");
      return;
    }
    setBusy(true);
    try {
      if (SUPABASE_CONFIGURED) {
        const { getBrowserClient } = await import("@/lib/supabase");
        const { data, error: sbError } =
          await getBrowserClient().auth.signUp({
            email,
            password,
            options: { emailRedirectTo: `${location.origin}/auth/callback` },
          });
        if (sbError) throw new Error(sbError.message);
        if (data.session) {
          router.push("/dashboard");      // auto-confirm projects
          return;
        }
        setSent(true);                     // email-confirmation flow
      } else {
        await devLogin(email);
        router.push("/dashboard");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Signup failed");
    } finally {
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
        {sent ? (
          <>
            <h1 className="mt-6 text-2xl font-medium leading-[1.13] tracking-tight text-ink">
              Check your email
            </h1>
            <p className="mt-2 text-[14px] leading-[1.4] text-subtle">
              We sent a confirmation link to <b>{email}</b>. Click it to
              activate your account, then sign in.
            </p>
            <Link href="/login" className="btn btn-primary mt-6 w-full">
              Back to sign in
            </Link>
          </>
        ) : (
          <>
            <h1 className="mt-6 text-2xl font-medium leading-[1.13] tracking-tight text-ink">
              Create your account
            </h1>
            <p className="mt-2 text-[14px] leading-[1.25] text-subtle">
              Analyst accounts for the Prahari console.
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
              <div>
                <label className="block">
                  <span className="label mb-1.5 block">password</span>
                  <span className="relative block">
                    <input
                      type={showPw ? "text" : "password"}
                      required
                      minLength={8}
                      autoComplete="new-password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="at least 8 characters"
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
                {password && (
                  <div className="mt-2 flex items-center gap-2" aria-live="polite">
                    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-paper-3">
                      <div
                        className="h-full rounded-full transition-all duration-300"
                        style={{
                          width: `${(strength.score / 5) * 100}%`,
                          background: strength.hue,
                        }}
                      />
                    </div>
                    <span className="label" style={{ color: strength.hue }}>
                      {strength.label}
                    </span>
                  </div>
                )}
              </div>
              <label className="block">
                <span className="label mb-1.5 block">confirm password</span>
                <input
                  type={showPw ? "text" : "password"}
                  required
                  autoComplete="new-password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  aria-invalid={!!fieldError()}
                  placeholder="repeat it"
                  className="w-full rounded-[4px] border border-line bg-white px-3 py-2.5 text-[15px] text-ink placeholder:text-faint focus:border-[#0000ee] focus:outline-none"
                />
              </label>
              {fieldError() && (
                <p className="text-[13px]" style={{ color: "var(--color-critical)" }}>
                  {fieldError()}
                </p>
              )}
              <label className="flex items-start gap-2.5 text-[13px] leading-[1.4] text-subtle">
                <input
                  type="checkbox"
                  checked={accepted}
                  onChange={(e) => setAccepted(e.target.checked)}
                  className="mt-0.5"
                  required
                />
                <span>
                  I use Prahari passively, on captures I own or am authorized
                  to analyze. No live traffic is ever probed.
                </span>
              </label>
              {error && <ErrorNote message={error} />}
              <button type="submit" disabled={busy} className="btn btn-primary group w-full">
                {busy ? "Creating…" : "Create account"}
                {!busy && (
                  <ArrowRight size={15} weight="bold" className="transition-transform duration-200 group-hover:translate-x-0.5" aria-hidden />
                )}
              </button>
            </form>
            <p className="mt-5 text-center text-[13px] leading-[1.25] text-subtle">
              Already registered?{" "}
              <Link href="/login" className="underline underline-offset-2">Sign in</Link>
            </p>
          </>
        )}
      </motion.div>
    </main>
  );
}
