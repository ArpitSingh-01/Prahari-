"use client";

/** API client.
 *
 * Open access model: no auth, no tokens. The only resilience logic here is
 * the cold-start retry ladder for the free-tier analysis engine (it sleeps
 * when idle; the first request after a sleep can take up to a minute).
 */

const BASE =
  process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "") ||
  "http://localhost:8000";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
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

async function fetchOnce(path: string, init: RequestInit) {
  const headers = new Headers(init.headers);
  if (init.body && !(init.body instanceof File) && !(init.body instanceof FormData))
    headers.set("Content-Type", "application/json");
  return fetch(`${BASE}${path}`, { ...init, headers });
}

async function fetchWithWakeRetry(
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
      return await fetchOnce(path, init);
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
  let res: Response;
  try {
    res = await fetchWithWakeRetry(path, init);
  } catch {
    throw WAKING;
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

/** Fetch a binary report (JSON/HTML/PDF) and trigger a browser download.
 * HTML is served inline, so it opens in a new tab; JSON/PDF are saved. */
export async function downloadReport(
  scanId: string,
  format: "json" | "html" | "pdf",
): Promise<void> {
  let res: Response;
  try {
    res = await fetchWithWakeRetry(`/api/scans/${scanId}/report.${format}`, {});
  } catch {
    throw WAKING;
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
