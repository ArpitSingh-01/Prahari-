# Deployment guide — Vercel + Render + Supabase (all free tier)

One-time setup, in dependency order. Total time: ~20 minutes.

## 0. Prerequisites

- This repository pushed to GitHub.
- Accounts on [vercel.com](https://vercel.com), [render.com](https://render.com),
  [supabase.com](https://supabase.com) (free tiers are fine).

## 1. Supabase (database + pcap storage)

1. **New project** → pick any name/region → set (and save) the DB password.
2. Wait for provisioning, then open **SQL Editor** → paste the full contents
   of [`backend/app/db/schema.sql`](../backend/app/db/schema.sql) → **Run**.
   This creates the `scans` + `scan_results` tables and locks RLS down to
   the service role (the anon key can read nothing).
3. **Storage** → **New bucket** → name exactly `pcaps` → **Private**
   (leave every option default) → Create. This is the only bucket; pcap
   files in it are auto-deleted ~24 h after each scan completes.
4. Collect three values (Project Settings → **API**):
   - **Project URL** → this is `SUPABASE_URL`
   - **service_role secret** → this is `SUPABASE_SERVICE_ROLE_KEY`
     (server-side only, never in the frontend, never in git)

> No Supabase Auth is used — the site is an open tool. There is nothing to
> configure under Authentication.

## 2. Render (backend)

1. Dashboard → **New → Web Service** → connect the GitHub repo.
2. When asked for the repo root, Render reads `backend/render.yaml`;
   if configuring manually instead:
   - **Root Directory:** `backend`
   - **Runtime:** Python 3
   - **Build:** `pip install -r requirements.txt`
   - **Start:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - **Health Check Path:** `/api/health`
3. **Environment variables** (Environment tab):

   | Key | Value |
   | --- | --- |
   | `SUPABASE_URL` | the Project URL from step 1 |
   | `SUPABASE_SERVICE_ROLE_KEY` | the service_role secret from step 1 |
   | `CORS_ORIGINS` | `https://<your-vercel-domain>` (fill in after step 3, then redeploy) |
   | `MAX_UPLOAD_MB` | `25` (already in render.yaml) |
   | `MAX_CONCURRENT_ANALYSES` | `2` (already in render.yaml) |

4. Deploy. Note the URL, e.g. `https://prahari-api.onrender.com` — this is
   the value for `NEXT_PUBLIC_API_URL` in step 3 and the `CORS_ORIGINS`
   target above. Set `CORS_ORIGINS` and redeploy once the Vercel domain exists.

## 3. Vercel (frontend)

1. **Add New → Project** → import the GitHub repo.
2. **Root Directory:** `frontend` (Vercel auto-detects Next.js; the build
   command is just `npm run build` — output is standalone, Vercel handles it).
3. **Environment variables:**

   | Key | Value |
   | --- | --- |
   | `NEXT_PUBLIC_API_URL` | the Render URL from step 2, e.g. `https://prahari-api.onrender.com` |

   (No Supabase env vars are needed by the frontend anymore — it talks only
   to the backend.)
4. Deploy. Note your domain, e.g. `https://prahari.vercel.app`.
5. Go back to Render → set `CORS_ORIGINS=https://prahari.vercel.app` → the
   backend redeploys.

## 4. Verify nothing is broken

1. `curl https://<render-url>/api/health` → `{"status": "ok", "db": "ok"}`.
   If `db` says `degraded`, the Supabase URL/key pair is wrong.
2. Open the Vercel domain → **New scan** → upload
   `backend/fixtures/pcaps/mixed.pcap` → Run analysis → expect 11 sessions,
   22 findings, grade F.
3. Check the Reports tab downloads all three formats.
4. If the browser blocks calls with a CORS error, the `CORS_ORIGINS` value
   doesn't exactly match the Vercel domain (scheme + host, no trailing slash).

## Keeping the free tiers alive

- **Render sleeps** after ~15 min without traffic. The frontend shows a
  "waking the analysis engine" state and retries for ~50 s, so the first
  visitor after a sleep waits up to a minute. To avoid the wait, point
  [cron-job.org](https://cron-job.org) (free) at
  `https://<render-url>/api/health` every 10 minutes.
- **Supabase pauses** after ~7 days of inactivity; the same health ping
  touches the database and keeps it active.

## Operational limits (free tier, by design)

| Limit | Value | Where enforced |
| --- | --- | --- |
| Upload size | 25 MB | `MAX_UPLOAD_MB`, rejected with 413 |
| Concurrent analyses | 2 | in-process semaphore, free-tier RAM guard |
| Pcap retention | 24 h after completion | opportunistic cleanup in the store |
| Scans | one shared workspace | open tool, no accounts |

If abuse ever becomes a concern, the cheapest next step is a shared
upload-rate limit or moving the site behind Cloudflare Access — the API
already rejects anything that isn't a pcap and caps sizes.
