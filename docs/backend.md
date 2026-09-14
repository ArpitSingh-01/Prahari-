# Backend — Prahari (SecureMailScope)

Backend specification for SIH 2026 PS 26159 — *Prahari — SecureMailScope ·
AI-Assisted Cryptographic Security Posture Assessment for SMTP/IMAP/POP3
email traffic from PCAP captures.* This document matches the tree as it
exists; where a capability is planned but absent, it is marked as such.

Hosting reality this spec is built around: **FastAPI on Render free tier**
(512 MB RAM, spins down after ~15 min idle, no Docker — native Python
build), **Supabase free tier** (Postgres 500 MB, Storage 1 GB, Auth,
project pauses after ~1 week of inactivity). Every design decision below
respects those limits.

---

## 1. Architecture

```
                    ┌──────────────────────────────┐
                    │  Next.js dashboard (Vercel)  │
                    └──────────────┬───────────────┘
                                   │ HTTPS + Bearer JWT (Supabase auth)
                                   ▼
┌──────────────────────────────────────────────────────────────────┐
│                 FastAPI backend (Render free)                     │
│                                                                    │
│  /api/scans (upload, list, detail, delete)                        │
│  /api/scans/{id}/analyze      ← 202 immediately; executor thread  │
│  /api/scans/{id}/status       ← polling for progress              │
│  /api/scans/{id}/sessions | findings | certificates | anomalies   │
│  /api/scans/{id}/report.{json,html,pdf}                           │
│  /api/model                   ← published ML metrics (model card) │
│  /api/stats                   ← public landing counters           │
│  /api/health                  ← keep-alive + DB-touching check     │
│                                                                    │
│  ┌──────────────── Analysis pipeline (in-process worker) ───────┐ │
│  │ 1 ingest · 2 protocol ID · 3 TCP reassembly (gap-flagging)   │ │
│  │ 4 STARTTLS/strip detection (in sessions.py)                 │ │
│  │ 5 TLS handshake parse · 6 X.509 extraction & validation    │ │
│  │ 7 25-rule engine · 8 features · 9 ML (GBM + IsolationForest)│ │
│  │ 10 bounded score fusion · 11 persistence · 12 reports       │ │
│  └──────────────────────────────────────────────────────────────┘ │
└──────────────┬───────────────────────────────┬───────────────────┘
               │ service-role key              │ storage
               ▼                               ▼
┌──────────────────────────┐    ┌──────────────────────────────┐
│ Supabase Postgres (RLS)  │    │ Supabase Storage              │
│ scans, scan_results,     │    │ pcaps/{user}/{scan}.pcap      │
│ reports                  │    │ (deleted ~24 h after scan)    │
└──────────────────────────┘    └──────────────────────────────┘
```

Key decisions and why:

- **Parsing happens in the backend, not the browser.** scikit-learn is
  Python-only, and the same pipeline must run for API-only use.
- **In-process worker (`run_in_executor` on a bounded `ThreadPoolExecutor`
  guarded by an `asyncio.Semaphore`) instead of Celery/Redis.** Render
  free gives one service; Celery needs a broker. The semaphore +
  `MAX_CONCURRENT_ANALYSES=2` keep the 512 MB box from self-DoS during
  judging.
- **`dpkt`, never `scapy`, for PCAP parsing.** scapy materializes packets
  as heavy objects; dpkt reads raw structs. TCP reassembly is ours (§4.3).
- **No `pyshark`/`tshark` dependency** — needs the Wireshark binary, which
  Render's native Python environment doesn't provide.
- **One JSON column instead of six tables.** The pipeline's result dict
  (`scan_results.data`) is the single source of truth; sessions/findings/
  certs/anomalies are derived views served by the API. RLS on `scans` is
  the user boundary; the service-role key writes.
- **PCAPs live in Supabase Storage, not the DB**, deleted ~24 h after scan
  completion (opportunistic cleanup on list requests — no cron on the
  free tier).

### Repository layout (Render Root Directory = `backend/`)

```
backend/
├─ requirements.txt
├─ runtime.txt                    # python-3.11
├─ render.yaml                    # service definition (committed)
├─ .env.example                   # var names only, never real secrets
├─ ml/
│  ├─ train.py                    # offline: train models, write metrics.json
│  └─ models/                     # risk_clf.joblib · anomaly_iforest.joblib
│  │                              # · metrics.json (all committed)
└─ app/
   ├─ main.py                     # FastAPI app, CORS (explicit origins; '*' rejected)
   ├─ config.py                   # pydantic-settings env
   ├─ auth.py                     # Supabase JWT verify (JWKS, HS256 fallback,
   │                              #   dev-<user> local mode)
   ├─ deps.py                     # store singleton, executor, analysis semaphore
   ├─ worker.py                   # executor-thread pipeline runner
   ├─ routers/
   │  ├─ scans.py                 # upload/list/detail/delete/analyze/status/
   │  │                           #   sessions/findings/certs/anomalies/summary
   │  └─ reports.py               # report.{json,html,pdf} · /api/model · /api/stats
   ├─ pipeline/
   │  ├─ ingest.py  protocols.py  reassembly.py  sessions.py
   │  ├─ tls_parser.py  certificates.py  rules.py  features.py
   │  └─ score.py  runner.py       # runner = pcap bytes → result dict
   ├─ ml_runtime/predict.py       # load joblib once, predict, explain, metrics
   ├─ reports/builder.py          # JSON native · HTML (Jinja2) · PDF (ReportLab)
   └─ db/
      ├─ schema.sql               # §3 DDL, applied via Supabase SQL editor
      └─ client.py                # LocalStore + SupabaseStore (reads THROUGH DB)
└─ tests/
   ├─ test_pipeline.py            # 54 golden + API tests (local mode)
   ├─ test_supabase.py            # live integration suite (opt-in: --supabase)
   └─ conftest.py                 # --supabase flag
```

Note: STARTTLS/strip detection lives in `pipeline/sessions.py`
(`_split_starttls_stream`), not a separate `transitions.py`; persistence
lives in `db/client.py` + `worker.py`, not a `persist.py`; the sessions/
findings/certificates/anomalies endpoints live in `routers/scans.py`. This
document used to claim a finer-grained tree than was built — it now
describes what exists.

---

## 2. Tech stack (pinned)

| Layer | Choice | Version pin | Notes |
| --- | --- | --- | --- |
| Framework | FastAPI | `fastapi>=0.115` | async, OpenAPI docs free |
| Server | Uvicorn | `uvicorn[standard]` | single worker (RAM) |
| PCAP parsing | dpkt | `dpkt>=1.9.8` | raw speed, low memory |
| TLS parsing | custom | `tls_parser.py` | dpkt doesn't parse TLS payloads |
| Certificates | cryptography | `cryptography>=43` | X.509 parse, chain, key info |
| Rule engine | custom | `rules.py` | §4.7 |
| ML | scikit-learn | `scikit-learn>=1.5` | IsolationForest + GradientBoosting |
| Model persistence | joblib | `joblib>=1.4` | committed in `ml/models/` |
| Reports | Jinja2 + ReportLab | `jinja2`, `reportlab>=4` | HTML + PDF; JSON native |
| DB client | supabase-py | `supabase>=2` | storage + service-role DB |
| Config | pydantic-settings | `>=2.3` | env + validation |

Python 3.11 on Render (`runtime.txt`); dev-tested on 3.13.

---

## 3. Data model (Supabase Postgres) — `app/db/schema.sql`

Auth is Supabase Auth (`auth.users`). Product tables live in `public`
with **RLS on** — users see only their own scans. There are deliberately
**no GENERATED columns**: `is_expired` / `days_to_expiry` depend on
`now()`, which Postgres rejects in `GENERATED ALWAYS … STORED` (not
IMMUTABLE); the pipeline computes them at insert time instead.

```sql
create table public.scans (
  id            uuid primary key,                  -- backend-generated
  user_id       uuid not null references auth.users(id) on delete cascade,
  name          text not null,
  file_size     bigint not null,
  file_path     text not null,                     -- storage object path
  status        text not null default 'uploaded'
                check (status in ('uploaded','parsing','complete','failed')),
  progress      smallint not null default 0,
  error         text,
  posture_score smallint check (posture_score between 0 and 100),
  grade         char(1) check (grade in ('A','B','C','D','F')),
  protocol_counts jsonb not null default '{}',
  session_count int,
  started_at    timestamptz,
  completed_at  timestamptz,
  created_at    timestamptz not null default now()
);

-- full pipeline JSON — the API's single source of truth
create table public.scan_results (
  scan_id    uuid primary key references public.scans(id) on delete cascade,
  data       jsonb not null,
  updated_at timestamptz not null default now()
);

create table public.reports (
  id           uuid primary key default gen_random_uuid(),
  scan_id      uuid not null references public.scans(id) on delete cascade,
  format       text not null check (format in ('json','html','pdf')),
  file_path    text not null,
  generated_at timestamptz not null default now()
);
```

RLS: `"own scans"` on `scans` (`auth.uid() = user_id`); `scan_results`
and `reports` check ownership through the parent scan row.

**Storage buckets**: `pcaps` and `reports`, both **private** — written and
read by the backend with the service-role key (the anon key never touches
them). Path convention `<user_id>/<scan_id>.pcap`. Retention: pcap objects
deleted ~24 h after scan completion by `SupabaseStore.cleanup_expired_pcaps()`,
piggybacked on list requests (no scheduler on free tier).

**Why one JSON blob is fine here:** a scan's derived data (sessions,
findings, certs) is always read together, always by the owner, and a full
result is well under 1 MB. 500 MB of Postgres holds thousands of scans.
RLS on `scans` is the entire user boundary — the JSON never crosses users.

---

## 4. Analysis pipeline (module by module)

### 4.1 Ingest — `pipeline/ingest.py`
- Input: uploaded pcap bytes. Classic pcap **and pcapng** (dpkt readers),
  link layers Ethernet / Linux SLL / raw IP normalized away.
- Yields `(ts, src, sport, dst, dport, seq, flags, payload, frame_no)` for
  TCP packets only. Frame numbers are monotonic across the whole read —
  findings cite them as evidence.

### 4.2 Protocol identification — `pipeline/protocols.py`
Payload evidence is authoritative, ports only tie-break: SMTP `220` banner +
`EHLO/MAIL FROM`, IMAP `* OK` + tagged commands, POP3 `+OK` + `USER/PASS`.
Handles mail on nonstandard ports (a PS deliverable). Encrypted implicit
sessions fall back to port hints since payloads are ciphertext.

### 4.3 TCP reassembly — `pipeline/reassembly.py`
- Flows keyed by address pairs; per-direction `DirectionStream` with
  bounded 4 MB caps (overflow flagged `truncated`, surfaced on the session).
- **Wraparound-aware ordering:** sequence numbers are unwrapped relative to
  the first segment (RFC 1983 serial arithmetic) — a stream crossing 2^32
  sorts correctly.
- **Honesty on gaps:** reassembly stops at the first missing segment and
  flags the stream `reassembly_incomplete` (hole offset recorded). A
  forensic tool must never fabricate contiguity. Both flags surface on the
  session, in `meta`, and in the UI.
- Retransmissions and overlaps deduped; duplicates + reordering combined
  are golden-tested.

### 4.4 STARTTLS & strip detection — `pipeline/sessions.py`
`_split_starttls_stream()` splits the plaintext preamble from the TLS
section of an upgraded flow:
- `STARTTLS`/`STLS` command + server acceptance → `transport='starttls'`,
  `started_plain=True`.
- **Strip/downgrade (differentiator #2):** client sent STARTTLS but no
  ClientHello followed → `transport='plaintext'` + finding **CFG-004**.
- **No-STARTTLS-advert (rule CFG-005, now live):** a plaintext SMTP session
  on 25/587 whose server EHLO response (captured in `session._ehlo_blob`)
  never advertises STARTTLS → CFG-005 fires from `evaluate_session`.
- Implicit ports: first bytes must be a ClientHello, else CFG-003.

### 4.5 TLS handshake reconstruction — `pipeline/tls_parser.py`
Custom record/handshake parser over reassembled streams: ClientHello,
ServerHello, Certificate (≤1.2), SKE/CKE, CCS, Finished, Alerts.
Extracts offered-vs-chosen ciphers (the offered/selected mismatch analysis
is differentiator #3), SNI, EMS, renegotiation_info, session resumption,
negotiated version incl. TLS 1.3 via supported_versions. TLS 1.3:
handshake parameters visible, certificate encrypted — reported as such.

### 4.6 Certificates — `pipeline/certificates.py`
DER blobs → `cryptography.x509`. Chain signature verification along offered
order, self-signed self-verification, validity window vs now, SNI/hostname
match, key size/hash strength. Flags: expired / not-yet-valid /
expiring ≤30d / weak key / **weak signature (SHA-1/MD5)** / hostname
mismatch / chain issues. `_verify_sha1_rsa()` does manual PKCS#1 v1.5
verification because some `cryptography` builds silently refuse SHA-1.

### 4.7 Weak-crypto rule engine — `pipeline/rules.py` (25 rules)

The deterministic core. Score = `100 − Σ weights` per session, aggregated
per scan (sessions weighted by their own risk). Rules carry severity,
weight, NIST/RFC/BSI/CERT-In reference and remediation text — the
compliance mapping comes free in every report (differentiator #6).

| Rule | Fires when | Sev | Wt |
| --- | --- | --- | --- |
| PRT-001 | Cleartext email session (no TLS) | critical | 40 |
| CFG-003 | Implicit-TLS port serving plaintext | critical | 40 |
| CFG-004 | STARTTLS stripped / cleartext fallback | critical | 35 |
| CFG-005 | EHLO advertises no STARTTLS (SMTP 25/587) | high | 15 |
| TLS-001 | SSLv2–TLS 1.1 negotiated | critical | 35 |
| CPR-001 | NULL/EXPORT/anonymous suite | critical | 40 |
| CPR-002 | RC4/3DES/IDEA/SEED suite | critical | 35 |
| CPR-003 | CBC suite in TLS 1.2 (Lucky13) | medium | 10 |
| CPR-004 | Server chose weakest mutually-offered suite | high | 15 |
| PFS-001 | No forward secrecy (RSA kex) | medium | 15 |
| CFG-006 | Resumption without extended master secret | medium | 10 |
| CFG-007 | Insecure renegotiation | high | 20 |
| ALR-001 | Fatal handshake alert (40/70/71) | high | 20 |
| CRT-001/002/003 | Expired / not-yet-valid / expiring ≤30d | crit/high/low | 30/20/5 |
| CRT-004 | Self-signed certificate | high | 20 |
| CRT-005 | Weak public key (RSA<2048, EC<256, DSA) | critical | 30 |
| CRT-006 | Weak signature hash (MD5/SHA-1) | high | 25 |
| CRT-007 | Hostname mismatch vs SNI | high | 20 |
| CRT-008 | Incomplete/broken chain | medium | 10 |
| CRE-001 | Cleartext credentials observed (redacted) | critical | 40 |
| PQC-001 | Quantum-vulnerable kex (no PQC path) — advisory, not scored | info | 0 |
| XSE-001 | Cert changed between sessions of same host | medium | 10 |
| XSE-002 | TLS version regression on same host | high | 20 |

Findings are ordered critical→info then by descending weight (`score.SEVERITY_ORDER`)
— prioritized ordering is a property of the core output and of report.json,
not just the PDF.

### 4.8 Features — `pipeline/features.py`
17 numeric features per session (both models share them): TLS version num,
cipher strength/id, PFS flag, cert key bits + sig-alg id, days valid/to
expiry, self-signed flag, chain-issue count, transport id, alert count,
renegotiation, resumption, log duration/bytes.

### 4.9 ML layer — `ml/` (no fine-tuning, no GPU)
1. **Risk classification** — `GradientBoostingClassifier` (200 est.),
   4 classes. Labels come from the rule engine over the synthetic corpus:
   self-labeled supervised learning that is defensible because the labels
   derive from published guidance, not opinion. Committed as
   `ml/models/risk_clf.joblib`; Render never trains at runtime.
2. **Anomaly detection** — `IsolationForest` (contamination 0.05) fitted on
   **clean sessions only** (the healthy baseline). Explanations are
   per-feature z-scores against that baseline → "TLS version is 3.1σ below
   the observed baseline" narratives in UI and reports.
3. **Published metrics** — `ml/train.py` computes holdout + 5-fold accuracy,
   per-class + macro precision/recall/F1, the confusion matrix, train/test
   sizes and clean-baseline flag rates, and writes `ml/models/metrics.json`
   (committed). Served at `/api/model`, rendered as the Settings → Model
   card. Current: holdout acc 96.4%, CV 98.2%, macro F1 0.73.
4. **LLM narrative: not implemented.** `LLM_API_KEY` is reserved in config
   but no call is made; the executive summary is templated. The plan doc's
   §4.9.3 is aspirational and stays out of the product until it earns its
   latency budget.

### 4.10 Score fusion — `pipeline/score.py` (rules + ML, bounded)

The PS plan requires *score fusion: rules + ML*. The implemented contract:

- **`rule_score`** = 100 − Σ rule weights (per session and per scan,
  scan-weighted by session risk). The compliance anchor — always reported
  separately, never overwritten.
- **`ml_adjustment`** (per session) = `max_session × w_anom × w_conf`
  where `w_anom` = 1.0 if the IsolationForest flags the session else 0.35,
  and `w_conf` = classifier probability mass on any bad class
  (critical/high/medium). Non-negative only — the AI can deepen a verdict
  the rules already imply, never soften one.
- **Scan-level fusion** = `rule_score − min(Σ session adjustments, 10)`,
  clamped [0, 100]. Per-session cap 2 points (`runner.ML_MAX_*`).
- **Clean invariant:** a session with `rule_score = 100` adjusts 0; a scan
  at 100 stays exactly 100/A. Locked by golden tests on
  `all-clean-gold.pcap` and `after-remediation.pcap`.
- All three numbers are in the API payload, session dicts
  (`rule_score`, `ml_adjustment`, `risk_score`), the scan posture, and a
  fusion-method paragraph in every HTML/PDF report.

### 4.11 Persistence & worker — `worker.py`, `db/client.py`
`analyze_pcap()` (pure, no I/O) runs on the executor thread with a
progress callback that updates the scan row; `result_to_dict()`
serializes; the store persists. `SupabaseStore` **reads through the
database** (the in-memory dicts are a write-side cache) so scans survive
Render restarts and cold starts; `LocalStore` mirrors the interface
in-memory so the whole test suite runs offline. Failures → status
`failed` + error string, never a zombie scan.

### 4.12 Reports — `reports/builder.py`
All three builders accept raw `analyze_pcap()` output or the dict form
(sessions normalized at entry — calling `build_pdf(analyze_pcap(...))`
directly is golden-tested). JSON schema `prahari.report/v1`; HTML/PDF
include: fusion line (rule − adjustment → fused), executive summary,
findings grouped by severity with references + remediation, session
inventory with ML risk column, **AI anomaly analysis** (z-score
narratives, or an explicit "no anomalies" statement), certificate
inventory, **compliance-mapping appendix**, and the fusion-method
paragraph.

---

## 5. API specification

Base: `https://<app>.onrender.com/api` · Auth: `Authorization: Bearer
<supabase_jwt>` on every scan route (dev-`<user>` in local mode). JWTs
verified via Supabase JWKS (cached 1 h), HS256+`SUPABASE_JWT_SECRET`
fallback, or the documented local dev path. Writes use the service-role
key server-side; the browser never talks to Postgres directly.

| Method | Path | Purpose | Notes |
| --- | --- | --- | --- |
| GET | `/health` | uptime probe | touches the store (keeps Supabase warm too) |
| GET | `/stats` | public counters | real numbers only; model info included |
| GET | `/model` | model card | published metrics from metrics.json |
| POST | `/scans` | multipart upload | streamed to tempfile; magic sniff; 413 > 25 MB; sanitized filename |
| GET | `/scans` | list own scans | `?limit&offset`; triggers pcap-retention cleanup |
| GET/DELETE | `/scans/{id}` | detail / delete | deletes storage objects; ownership enforced |
| POST | `/scans/{id}/analyze` | start pipeline | 202 immediately; semaphore-capped; 409 if running |
| GET | `/scans/{id}/status` | progress poll | `{status, progress, error}` |
| GET | `/scans/{id}/sessions[/{sid}]` | sessions | filters `?protocol&transport&grade&anomaly`; detail includes findings + evidence |
| GET | `/scans/{id}/findings` | findings | `?severity&category`; severity-then-weight ordered |
| GET | `/scans/{id}/certificates` | cert inventory | includes PEM |
| GET | `/scans/{id}/anomalies` | flagged sessions | joined with z-score explanations |
| GET | `/scans/{id}/summary` | executive summary | template text + posture |
| GET | `/scans/{id}/report.{json,html,pdf}` | exports | generated on demand |

Errors are `{"detail": "..."}` with 400/401/404/409/410/413. List
endpoints return `{items, total, limit, offset}`.

---

## 6. Render deployment (free-tier specifics)

- Native Python service (no Docker): build `pip install -r requirements.txt`,
  start `uvicorn app.main:app --host 0.0.0.0 --port $PORT`. `render.yaml`
  committed.
- Env vars (dashboard, never committed; list in `.env.example`):
  `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `SUPABASE_ANON_KEY`,
  `SUPABASE_JWT_SECRET`, `CORS_ORIGINS` (the Vercel domain — **`*` entries
  are rejected** since credentialed CORS needs concrete origins),
  `MAX_UPLOAD_MB=25`, `MAX_CONCURRENT_ANALYSES=2`, `LLM_API_KEY` (reserved).
- **Cold starts ~50 s.** Mitigations: `/api/health` pinged by cron-job.org
  every 10 min (also keeps Supabase from pausing); the frontend retries
  the first API call for ~50 s with an explicit "waking the analysis
  engine" state.
- **Memory discipline:** uploads stream to `tempfile` (never buffered in
  RAM), reassembly buffers bounded at 4 MB/direction, the worker frees
  intermediates after persisting, concurrency semaphore-capped.
- **Timeouts:** Render's ~100 s request limit — `/analyze` returns 202
  immediately; work happens on the executor; the frontend polls `/status`.

---

## 7. Security checklist

- Secrets via env vars only; the service-role key never leaves the backend.
- CORS: explicit origins (the Vercel domain), `*` stripped at config level.
- Upload: filename sanitized (`[^A-Za-z0-9._-]` → `_`), pcap/pcapng magic
  sniffed before anything is written, size cap enforced during streaming.
- `MAX_CONCURRENT_ANALYSES` semaphore + bounded executor = self-DoS guard.
- Credentials redaction: cleartext passwords stored only as bullet strings
  or lengths; golden-tested (`test_credentials_are_redacted`).
- Pcap retention ~24 h; RLS is the cross-user boundary; live RLS isolation
  covered by the opt-in `--supabase` suite.

---

## 8. Test & validation strategy

- **Synthetic corpus** (`scripts/gen_certs.py` + `gen_traffic.py`, pure
  Python, no driver): 21 scenario pcaps incl. a genuinely SHA-1-signed
  cert (minted by computing RSA over `DigestInfo(SHA-1‖TBS)` directly,
  because modern libraries refuse SHA-1 signing — acceptance check:
  `signature_hash_algorithm.name == "sha1"`).
- **Golden tests** (26 scenario assertions + gold captures + API e2e +
  reassembly + fusion + redaction + differentiator checks = 44): each
  scenario must fire at least its expected rule set; `all-clean-gold` and
  `after-remediation` must produce ZERO findings and exactly 100/A with
  zero ML adjustment.
- **Reassembly properties:** retransmits, wraparound at 2^32, a missing
  middle segment (stream must STOP at the hole and flag), duplicate +
  reordering combined, size-cap truncation flag.
- **Fusion contract:** clean sessions adjust 0; bounded ≤2/session ≤10/scan;
  fused ≤ rule score; dirty captures may only drop.
- **API e2e** (TestClient, local mode): upload → analyze → poll → detail →
  sessions → findings → certs → all three report formats → delete; 401
  without a token; 400 non-pcap; 413 oversize.
- **Live Supabase suite** (`pytest --supabase` + env vars; skipped by
  default so CI stays green offline): schema contract, RLS isolation with
  a real second session, storage round-trip, SupabaseStore read-through
  across instances.
