"use client";

/** API client.
 *
 * Two modes, resolved at runtime:
 * - Supabase configured (NEXT_PUBLIC_SUPABASE_URL set): the session lives in
 *   cookies managed by @supabase/ssr (see lib/supabase.ts); the bearer token
 *   is the current Supabase access token, refreshed transparently on 401.
 * - Local/demo mode: the documented dev token (`dev-<user>`), with a
 *   one-time migration from the legacy `sms_token` key so existing local
 *   sessions don't break.
 */

const BASE =
  process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "") ||
  "http://localhost:8000";

export const SUPABASE_CONFIGURED = !!process.env.NEXT_PUBLIC_SUPABASE_URL;

const TOKEN_KEY = "prahari_token";
const LEGACY_TOKEN_KEY = "sms_token";     // pre-rename key; migrate on read

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  let token = window.localStorage.getItem(TOKEN_KEY);
  if (!token) {
    const legacy = window.localStorage.getItem(LEGACY_TOKEN_KEY);
    if (legacy?.startsWith("dev-")) {
      window.localStorage.setItem(TOKEN_KEY, legacy);
      window.localStorage.removeItem(LEGACY_TOKEN_KEY);
      token = legacy;
    }
  }
  return token;
}

export function isLoggedIn(): boolean {
  return !!getToken();
}

/** Dev/local mode sign-in: the backend accepts `dev-<user>` bearer tokens. */
export async function devLogin(email: string): Promise<void> {
  if (!/^[^@\s]+@[^@\s]+$/.test(email)) throw new Error("Enter a valid email");
  const user = email.split("@")[0].replace(/[^a-zA-Z0-9_-]/g, "") || "demo";
  window.localStorage.setItem(TOKEN_KEY, `dev-${user}`);
}

export function logout(): void {
  window.localStorage.removeItem(TOKEN_KEY);
  window.localStorage.removeItem(LEGACY_TOKEN_KEY);
}

/** Current Supabase access token, or null in local mode / signed out. */
export async function supabaseToken(): Promise<string | null> {
  if (!SUPABASE_CONFIGURED) return null;
  const { getBrowserClient } = await import("@/lib/supabase");
  const { data } = await getBrowserClient().auth.getSession();
  return data.session?.access_token ?? null;
}

/** Sign out of Supabase and clear the local token. */
export async function supabaseLogout(): Promise<void> {
  if (SUPABASE_CONFIGURED) {
    const { getBrowserClient } = await import("@/lib/supabase");
    await getBrowserClient().auth.signOut();
  }
  logout();
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/** Session-expired signal for the global handler (redirect + toast). */
export class SessionExpired extends ApiError {
  constructor() {
    super(401, "Your session expired. Sign in again.");
  }
}

const WAKING = new Error(
  BASE.startsWith("http://localhost") || BASE.startsWith("http://127.")
    ? "Cannot reach the analysis engine — is the backend running? " +
      "Start it with:  cd backend && uvicorn app.main:app --reload"
    : "Cannot reach the analysis engine yet — it may be waking up from " +
      "sleep (this takes up to a minute on the free tier). Retrying…",
);

/** True when the error is the cold-start/unreachable engine signal. */
export function isWakingError(err: unknown): boolean {
  return err === WAKING;
}

async function fetchOnce(token: string | null, path: string, init: RequestInit) {
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !(init.body instanceof File) && !(init.body instanceof FormData))
    headers.set("Content-Type", "application/json");
  return fetch(`${BASE}${path}`, { ...init, headers });
}

async function fetchWithWakeRetry(
  token: string | null,
  path: string,
  init: RequestInit,
): Promise<Response> {
  // Against a local dev backend, a connection failure means "not started" —
  // surface it immediately. Only the remote (free-tier) engine gets the
  // ~50 s cold-start retry ladder.
  const isLocal = BASE.startsWith("http://localhost") || BASE.startsWith("http://127.");
  const attempts = isLocal ? 1 : 4;
  const waits = isLocal ? [0] : [0, 4000, 15000, 30000];   // ~49s — covers a cold start
  for (let i = 0; i < attempts; i++) {
    if (waits[i]) await new Promise((r) => setTimeout(r, waits[i]));
    try {
      return await fetchOnce(token, path, init);
    } catch {
      if (i === attempts - 1) throw WAKING;
    }
  }
  throw WAKING;                            // unreachable
}

export async function api<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  let token = getToken();
  if (SUPABASE_CONFIGURED && !token) token = await supabaseToken();

  let res: Response;
  try {
    res = await fetchWithWakeRetry(token, path, init);
  } catch {
    throw WAKING;
  }

  // One silent refresh on 401 (Supabase mode): a fresh access token fixes
  // expiry; if it fails the session is genuinely gone.
  if (res.status === 401 && SUPABASE_CONFIGURED) {
    const refreshed = await supabaseToken();
    if (refreshed && refreshed !== token) {
      try {
        res = await fetchWithWakeRetry(refreshed, path, init);
      } catch {
        throw WAKING;
      }
    }
    if (res.status === 401) throw new SessionExpired();
  }

  if (res.status === 204) return undefined as T;
  const text = await res.text();
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  if (!res.ok) {
    const detail =
      (body as { detail?: string })?.detail || `Request failed (${res.status})`;
    throw new ApiError(res.status, detail);
  }
  return body as T;
}

/** Fetch a binary report (JSON/HTML/PDF) with auth and trigger a browser
 * download. Plain <a href> links can't carry the Authorization header.
 * HTML is served inline, so it opens in a new tab; JSON/PDF are saved. */
export async function downloadReport(
  scanId: string,
  format: "json" | "html" | "pdf",
  name = "capture",
): Promise<void> {
  let token = getToken();
  if (SUPABASE_CONFIGURED && !token) token = await supabaseToken();

  let res: Response;
  try {
    res = await fetchWithWakeRetry(token, `/api/scans/${scanId}/report.${format}`, {});
  } catch {
    throw WAKING;
  }

  // One silent refresh on 401 (Supabase mode), same as api().
  if (res.status === 401 && SUPABASE_CONFIGURED) {
    const refreshed = await supabaseToken();
    if (refreshed && refreshed !== token) {
      try {
        res = await fetchWithWakeRetry(refreshed, `/api/scans/${scanId}/report.${format}`, {});
      } catch {
        throw WAKING;
      }
    }
    if (res.status === 401) throw new SessionExpired();
  }

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    let detail = `Report request failed (${res.status})`;
    try {
      detail = JSON.parse(text).detail || detail;
    } catch {
      if (text) detail = text.slice(0, 200);
    }
    throw new ApiError(res.status, detail);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  if (format === "html") {
    window.open(url, "_blank", "noopener");
  } else {
    const a = document.createElement("a");
    a.href = url;
    a.download = `prahari-report-${scanId.slice(0, 8)}.${format}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
  }
  // Give the browser a tick to start the navigation before releasing.
  setTimeout(() => URL.revokeObjectURL(url), 30_000);
}
