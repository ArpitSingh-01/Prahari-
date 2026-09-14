# Prahari

**Prahari — SecureMailScope · AI-Assisted Cryptographic Security Posture
Assessment** — Smart India Hackathon 2026, Problem Statement 26159 (NTRO).
*Prahari* (प्रहरी, "sentinel").

Upload a PCAP of SMTP/IMAP/POP3 traffic. Prahari passively reconstructs
every session, parses every TLS handshake, validates every certificate,
runs a 25-rule weak-cryptography engine mapped to NIST SP 800-52r2 / RFC
8996 / BSI TR-02102 / CERT-In guidance, layers ML risk classification +
Isolation Forest anomaly detection on top with a bounded, published score
fusion, and produces a 0–100 posture score with A–F grades, an interactive
dashboard with evidence drill-down, compliance mapping, and JSON/HTML/PDF
forensic reports.

## Repository layout

```
backend/    FastAPI + dpkt pipeline + scikit-learn  → Render (root dir: backend)
frontend/   Next.js 15 + Tailwind v4 + Recharts     → Vercel (root dir: frontend)
docs/       design.md · backend.md · frontend.md · implementation-plan.md · demo-script.md
```

## Quick start (local, no Docker, no Supabase required)

Backend (Python 3.11+):

```bash
cd backend
pip install -r requirements.txt
python scripts/gen_certs.py       # mint the cert corpus (incl. a REAL sha1-signed cert)
python scripts/gen_traffic.py     # generate scenario + training pcaps
python ml/train.py                # train risk classifier + anomaly model, write metrics.json
uvicorn app.main:app --reload     # http://localhost:8000  (docs at /docs)
```

Without Supabase env vars the backend runs in **local mode**: in-memory
storage and `Authorization: Bearer dev-<name>` tokens. The entire test
suite runs this way.

Frontend:

```bash
cd frontend
npm install
npm run dev                       # http://localhost:4567
```

(The dev script pins port 4567; the backend's default CORS already allows
`http://localhost:4567`. The backend above must be running on :8000 — the
frontend proxies all analysis calls to it.)

Open `/login` and either create an account (when Supabase env vars are
set) or click **Continue as demo analyst** (local mode: any email creates
a `dev-<user>` session). Upload `backend/fixtures/pcaps/mixed.pcap` and
explore.

Tests:

```bash
cd backend && python -m pytest tests/ -q          # 54 golden+API tests
cd backend && python -m pytest tests/ -q --supabase   # + live Supabase suite (opt-in, needs env)
cd frontend && npm run build                     # type-checked production build
```

## Score model: rules + ML fusion (the one-paragraph answer)

The deterministic rule engine alone produces the **rule score**
(100 − Σ rule weights — the compliance anchor, always reported separately).
The AI layer may then apply a **bounded negative adjustment**: each session
contributes at most 2 points (`adj = 2 × w_anom × w_conf`, where `w_anom`
is 1.0 when the IsolationForest flags the session and 0.35 otherwise, and
`w_conf` is the classifier's probability mass on any bad class), the scan
total is capped at 10, and the fused score is clamped to [0, 100]. The AI
can deepen a verdict the rules already imply — it never softens one, never
raises a clean session, and a capture with zero findings and zero anomalies
stays exactly 100/A (locked by golden tests). All three numbers
(`rule_score`, `ml_adjustment`, `score`) appear in the API, the UI and
every report, with the formula in the report appendix.

## The pipeline

`PCAP → protocol ID → TCP reassembly (wraparound-aware, gap-flagging) →
STARTTLS/strip detection → TLS handshake parse → X.509 extraction &
validation → 25-rule engine → feature extraction → GBM risk classifier +
Isolation Forest → bounded score fusion → JSON/HTML/PDF reports`

Rules-to-metrics chain: `ml/train.py` computes accuracy/precision/recall/F1
per class + macro, a confusion matrix and clean-baseline flag rates, and
publishes them to `backend/ml/models/metrics.json` — served at
`/api/model` and rendered as the **Model card** in Settings.

## Deployment

| Piece | Where | Root dir | Notes |
| --- | --- | --- | --- |
| Frontend | Vercel (hobby) | `frontend/` | env: `NEXT_PUBLIC_API_URL`, `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY` |
| Backend | Render (free) | `backend/` | build `pip install -r requirements.txt`, start `uvicorn app.main:app --host 0.0.0.0 --port $PORT`; env per `backend/.env.example` |
| Database/Auth | Supabase (free) | — | run `backend/app/db/schema.sql`, enable email auth, set redirect URLs to the Vercel domain, create private buckets `pcaps` + `reports` |

The committed ML models (`backend/ml/models/*.joblib` + `metrics.json`)
mean Render never trains at runtime. The frontend uses cookie-based
sessions (`@supabase/ssr`) with middleware that refreshes tokens on every
request and guards the app routes; in local mode it falls back to the
`dev-` token transparently. Render's free instance sleeps after ~15 min
idle: the frontend retries the first API call for ~50 s with an explicit
"waking the analysis engine" state, and `/api/health` (which touches the
DB, keeping Supabase active too) is pinger-friendly — keep it warm with a
cron-job.org ping every 10 min.

## Test corpus (27 pcaps, regenerate any time)

`python scripts/gen_certs.py && python scripts/gen_traffic.py` inside
`backend/` rebuilds everything with fresh certificate dates. The SHA-1
fixture is genuinely SHA-1-signed (minted by computing the RSA signature
over `DigestInfo(SHA-1‖TBS)` directly, since modern libraries refuse to
sign SHA-1) and exercises rule CRT-006 end-to-end.

| Pcap | What it demonstrates | Expected |
| --- | --- | --- |
| `mixed.pcap` | kitchen sink — all weak scenarios in one capture | 22 findings, grade F |
| `after-remediation.pcap` | same servers after fixes — pairs with mixed for the before/after demo | 100/A, clean |
| `all-clean-gold.pcap` | healthy SMTPS/IMAPS/POP3S + STARTTLS | 100/A, clean |
| `host-cert-swap.pcap` | same host presents different leaf certs (interception hint) | XSE-001 |
| `host-version-regression.pcap` | host drops TLS 1.2 → 1.0 mid-capture | XSE-002 + TLS-001 |
| `smtp-cleartext-auth.pcap` | AUTH LOGIN with base64 creds in cleartext, no STARTTLS offered | CRE-001 + PRT-001 + CFG-005 |
| `smtp-no-starttls-advert.pcap` | EHLO response never advertises STARTTLS | CFG-005 + PRT-001 |
| `imap-cleartext-login.pcap` | IMAP LOGIN creds in cleartext | CRE-001 + PRT-001 |
| `pop3-cleartext.pcap` | POP3 USER/PASS in cleartext | CRE-001 + PRT-001 |
| `starttls-stripped.pcap` | STARTTLS requested, server refused | CFG-004 |
| `smtp-tls10-rc4.pcap` | deprecated TLS 1.0 + RC4, weakest-suite selection | TLS-001 + CPR-002 + CPR-004 |
| `imap-expired-cert.pcap` | expired certificate | CRT-001 |
| `imap-expiring-soon.pcap` | cert expiring in 20 days | CRT-003 |
| `pop3s-not-yet-valid.pcap` | cert not valid yet | CRT-002 |
| `pop3s-weak-nopfs.pcap` | RSA-1024 key + no forward secrecy | CRT-005 + PFS-001 |
| `imaps-sha1-selfsigned.pcap` | **real** SHA-1-signed self-signed cert, CBC, no PFS | CRT-006 + CRT-004 + PFS-001 |
| `imap-hostname-mismatch.pcap` | cert SAN does not match the SNI sent | CRT-007 |
| `insecure-reneg.pcap` | mid-connection renegotiation without RFC 5746 | CFG-007 |
| `pqc-hybrid-kex.pcap` | TLS 1.3 negotiating hybrid X25519MLKEM768 | PQC-ready session, no findings |
| `handshake-failure.pcap` | fatal handshake_failure alert | ALR-001 |
| `good-smtps / imaps-good / pop3s-good / starttls-ok` | clean baselines | 100/A, clean |
| `train-1..4.pcap` | randomized ML training corpus (45 sessions each) | — |

Every scenario is locked by a golden-file pytest (54 tests), so rule
regressions fail CI loudly.

## Deliberate stack substitutions (and why)

The problem statement suggests a reference stack; we deviate in four
places, each forced by the deployment target (free-tier Vercel + Render +
Supabase) rather than preference:

1. **No Docker/compose.** The stack deploys as three managed services
   (Vercel frontend, Render backend, Supabase DB/auth/storage) — containers
   add nothing there and free tiers don't run them.
2. **ThreadPoolExecutor instead of Celery/Redis.** There is no free
   Redis broker; a bounded in-process executor plus a semaphore gives the
   same "202 immediately, analyze in background" behaviour within one
   512 MB instance.
3. **ReportLab instead of WeasyPrint.** WeasyPrint needs system cairo/
   pango libraries that the Render image doesn't ship; ReportLab is
   pure-Python and renders the same report structure.
4. **Polling (202 + status endpoint) instead of WebSocket.** A WebSocket
   dies silently when a free-tier instance sleeps and reboots; short-
   interval polling over the same 202 pattern survives sleep/wake with
   zero extra infrastructure.

## Honest limitations (stated, not hidden)

- **TLS 1.3 encrypts the certificate** after ServerHello: sessions
  negotiated at 1.3 show handshake parameters but no certificate chain.
- **No passive trust anchor:** offline PCAP analysis cannot verify a chain
  against live CA revocation; we verify chain signatures, self-consistency,
  validity windows and hostname/SNI match, and say exactly that.
- **The ML corpus is synthetic** (generated by `scripts/gen_traffic.py`),
  and the classifier's labels are derived from the rule engine — it learns
  published guidance, not field data. Metrics are published (model card)
  rather than hidden.
- **Reassembly honesty:** a TCP stream with a missing segment is *never*
  concatenated as if contiguous — the session is flagged
  `reassembly_incomplete` and the analysis covers the contiguous prefix.

## Honest-ML note

The risk classifier is trained on labels produced by the deterministic rule
engine (which itself derives from published guidance) over a synthetic
corpus generated by `backend/scripts/gen_traffic.py` — no fine-tuning, no
GPU, fully reproducible. The Isolation Forest learns a "healthy traffic"
baseline and flags sessions that deviate from it, with per-feature z-score
explanations. Published metrics: holdout accuracy 98.2%, 5-fold CV 96.9%,
macro F1 0.98 (see `backend/ml/models/metrics.json` or Settings → Model
card in the app).

Docs: [backend](docs/backend.md) · [frontend](docs/frontend.md) ·
[design](docs/design.md) · [demo script](docs/demo-script.md) ·
[implementation plan](docs/implementation-plan.md)
