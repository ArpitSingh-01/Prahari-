# Architecture

Prahari is a three-service system: a Next.js console (Vercel), a FastAPI
analysis engine (Render), and a Postgres + object storage backend
(Supabase). There are no user accounts — the workspace is open and shared;
capacity guards are the only boundary.

```
┌──────────────┐   HTTPS (JSON)    ┌──────────────────┐   service key   ┌────────────┐
│  frontend/   │ ────────────────► │  backend/        │ ──────────────► │  Supabase  │
│  Next.js 15  │ ◄──────────────── │  FastAPI + dpkt  │                 │  Postgres  │
│  Vercel      │  202 + polling    │  Render (free)   │                 │  + Storage │
└──────────────┘                   └──────────────────┘                 └────────────┘
```

## Data flow

1. **Upload** — the browser POSTs the pcap to `/api/scans`. The backend
   streams it to a temp file (magic + size checked), then stores the bytes
   in the private `pcaps` Storage bucket and a scan row in Postgres.
2. **Analyze** — `POST /api/scans/{id}/analyze` returns 202 immediately and
   a bounded thread pool runs the pipeline (`app/pipeline/runner.py`).
   Progress is polled from `/status`.
3. **Results** — the full analysis JSON lands in `scan_results` and is the
   API's single source of truth: sessions, findings, certificates,
   features, posture are all derived views of that JSON.
4. **Reports** — JSON/HTML/PDF are built on the fly from the result
   (`app/reports/builder.py`); there is no report table or bucket.
5. **Retention** — pcap bytes are deleted ~24 h after a scan completes
   (opportunistic cleanup on list requests). The analysis JSON persists.

## The pipeline (backend/app/pipeline/)

| Stage | Module | What it does |
| --- | --- | --- |
| Ingest | `ingest.py` | pcap/pcapng, Ethernet/SLL/raw link layers → TCP tuples with frame numbers + file offsets |
| Reassembly | `reassembly.py` | per-flow byte streams; wraparound-aware sequencing, retransmit/overlap removal, gap + truncation flags (never fabricates contiguity) |
| Protocol ID | `protocols.py` | SMTP/IMAP/POP3 from payload greetings/commands; ports only tie-break; encrypted mail derived from base protocol + transport |
| Sessions | `sessions.py` | STARTTLS/stripped/implicit/plaintext transport split, plaintext prelude capture, cleartext-credential scanner (redacted) |
| TLS | `tls_parser.py` | hand-written record/handshake parser: ClientHello/ServerHello/Certificate/SKE, alerts, extensions (SNI, EMS, renegotiation_info, supported_groups, key_share, supported_versions), TLS 1.3 awareness, renegotiation detection |
| Certificates | `certificates.py` | X.509 chain extraction + signature verification (incl. manual SHA-1 path), expiry, key sizes, SAN/SNI match |
| Rules | `rules.py` | 25 deterministic rules seeded from NIST SP 800-52r2 / RFC 8996 / BSI TR-02102 / CERT-In, each with severity, weight, reference, remediation; plus informational advisories (PQC-001) |
| Features | `features.py` | 21-feature numeric vector per session (inputs to both models) |
| Scoring | `score.py` | session/scan posture scores, A–F grades, cross-session host findings (XSE-001 cert swap, XSE-002 version regression), bounded rules+ML fusion |

The fusion contract: the rule score is the compliance anchor
(`100 − Σ weights`); ML may only deepen a verdict, at most 2 points per
session and 10 per scan, and a clean capture stays exactly 100/A (golden
test invariant). Full formula in the README and every report appendix.

## ML layer

- `ml/train.py` (offline, committed artifacts): GradientBoosting risk
  classifier (4 classes, labels derived from the rule engine) +
  IsolationForest anomaly detector (fitted on clean sessions only).
  Metrics published to `ml/models/metrics.json` → served at `/api/model`
  → rendered as the Model card in the app's Settings.
- `app/ml_runtime/predict.py` loads the joblib bundles once and predicts
  per session at scan time, with per-feature z-score explanations for
  anomalies. ML failure never breaks a scan (rules/scoring are additive).

## API surface (prefix `/api`)

```
POST   /scans                    upload pcap (multipart, 25 MB cap, magic-checked)
GET    /scans                    list (paginated)
GET    /scans/{id}               scan row
DELETE /scans/{id}               delete scan + stored pcap
POST   /scans/{id}/analyze       202 + background analysis
GET    /scans/{id}/status        progress polling
GET    /scans/{id}/summary       posture + narrative summary
GET    /scans/{id}/sessions      filter by protocol/transport/grade/anomaly
GET    /scans/{id}/sessions/{sid}  one session + its findings/advisories
GET    /scans/{id}/findings      filter by severity/category
GET    /scans/{id}/advisories    zero-weight informational rules
GET    /scans/{id}/certificates  all parsed certs
GET    /scans/{id}/anomalies     flagged sessions + z-score explanations
GET    /scans/{id}/report.{json,html,pdf}
GET    /model                    published model card
GET    /stats                    landing-page counters (real numbers only)
GET    /health                   uptime probe (touches the store)
```

## Store (`app/db/client.py`)

One interface, two implementations:

- `LocalStore` — in-memory dicts; used when Supabase env vars are absent
  (local dev, tests). Scans die with the process.
- `SupabaseStore` — extends LocalStore with read-through persistence:
  every write also goes to Postgres (`scans`, `scan_results`) and every
  read falls through to the DB when the in-process cache misses, so a
  fresh Render instance serves scans created by a previous one. Pcap
  bytes live in the private `pcaps` Storage bucket.

RLS is enabled on both tables with **no policies**: the backend uses the
service-role key (which bypasses RLS); a leaked anon key can read nothing.

## Frontend (frontend/)

- Landing (`app/page.tsx`) — marketing canvas + live counters from `/stats`.
- Console (`app/(app)/…`) — Dashboard (posture trend), New scan (single +
  batch upload), scan detail (Overview / Sessions / Findings /
  Certificates / Anomalies / Compliance / Reports tabs with score dial,
  charts, handshake timeline, evidence hex), Compare (before/after
  remediation delta), Settings (deployment info + model card).
- `lib/api.ts` — thin fetch wrapper with the free-tier cold-start retry
  ladder (~50 s) and blob-based report downloads.

## Free-tier survival notes

- Render sleeps after ~15 min idle: the frontend retries transparently;
  `/api/health` can be pinged by an external cron to stay warm.
- The analysis semaphore (`MAX_CONCURRENT_ANALYSES`) caps RAM on the
  512 MB instance; uploads stream through temp files, never buffered whole
  in memory twice.
- Supabase pauses after ~7 days inactivity: the same health ping keeps it
  active.
