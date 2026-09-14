# Implementation Plan — Prahari (SecureMailScope)

Execution plan for SIH 2026 PS 26159. Companion documents:
[`design.md`](design.md) (locked design system) · [`backend.md`](backend.md)
(backend + database spec) · [`frontend.md`](frontend.md) (frontend spec).

---

## 0. Repository & deployment layout

Monorepo, split by deployment target. **Vercel Root Directory = `frontend/`**,
**Render Root Directory = `backend/`** — each service is self-contained and
never reads across the boundary.

```
SIH-159/                          ← repo root (git)
├─ backend/                       ← Render (native Python, no Docker)
│  ├─ requirements.txt  runtime.txt  render.yaml  .env.example
│  ├─ ml/                         # train.py offline + committed joblib models
│  ├─ scripts/                    # gen_traffic.py · gen_certs.py (no Docker)
│  └─ app/                        # FastAPI: routers/ pipeline/ reports/ db/
├─ docs/                          # all planning documents (these files)
│  ├─ design.md  backend.md  frontend.md  implementation-plan.md
│  └─ ps/                         # problem statement source, pitch drafts
├─ frontend/                      ← Vercel (Next.js 15, self-contained)
│  ├─ tokens.css                  # canonical design tokens (self-contained)
│  └─ app/ components/ lib/ types/
└─ .gitignore                     # node_modules, .next, venv, .env, *.pcap temp
```

Deployment wiring:

| Service | Root dir | Build | Notes |
| --- | --- | --- | --- |
| Vercel (hobby) | `frontend/` | `next build` (auto) | env: `NEXT_PUBLIC_API_URL`, Supabase anon + URL |
| Render (free) | `backend/` | `pip install -r requirements.txt` | start: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`; env per backend.md §6 |
| Supabase (free) | — | run `backend/app/db/schema.sql` in SQL editor | enable Auth (email), create buckets `pcaps`/`reports` |

---

## 1. Team split (6 members — adjust to your team)

| Role | Members | Owns |
| --- | --- | --- |
| **Forensics core** | 2 | `pipeline/` — reassembly, TLS parser, certs, rule engine; the synthetic pcap generator (`scripts/`) |
| **ML + reports** | 1 | `ml/` + `ml_runtime/` + `reports/` — corpus labeling, IsolationForest + GBM, JSON/HTML/PDF reports |
| **Backend/API** | 1 | FastAPI routers, auth, Supabase schema + RLS + storage, Render deploy, keep-alive |
| **Frontend** | 2 | Next.js app — App Shell, workspace tabs, charts, upload flow, landing page, Vercel deploy |

The critical path is the **forensics core** (TLS parser + rule engine). Start
it on day one; everything else consumes its output. Frontend can build
against fixture JSON before the API exists (§3, Phase 1).

---

## 2. Phase plan (6 working weeks)

### Phase 0 — Foundations (Week 1, days 1–2)
- Repo init, folder skeleton, `.gitignore`, Supabase project, empty Vercel +
  Render services deployed with health-check stubs **on day 1** (deployment
  friction discovered early, not in week 5).
- `schema.sql` applied; auth (email) enabled; storage buckets created.
- Design tokens into `frontend/tokens.css`; fonts wired via `next/font`.
- **Gate:** hello-world on all three services; auth round-trip works.

### Phase 1 — Data engine (Week 1–2) ⚠ critical path
- `scripts/gen_certs.py`: mint good/expired/self-signed/weak-key/SHA-1 cert
  variants (pure `cryptography`).
- `scripts/gen_traffic.py`: pure-Python SMTP/IMAP/POP3 servers (`aiosmtpd` +
  sockets) wrapped in `ssl.SSLContext` per scenario; Python clients exercise
  implicit TLS + STARTTLS + stripped-STARTTLS paths.
- Capture scenario pcaps with Wireshark + Npcap loopback: good baseline,
  TLS 1.0, RC4, expired cert, weak key, no-PFS, cleartext,
  STARTTLS-stripped, mixed. ~10 labeled pcaps committed (small ones) to
  `docs/ps/corpus/` or shared drive.
- **Gate:** every scenario pcap opens in Wireshark and shows the intended
  weakness; a README maps scenario → expected findings.

### Phase 2 — Forensics pipeline (Week 2–3) ⚠ critical path
- `ingest.py` + `protocols.py` + `reassembly.py` (flow tracking, seq
  handling, retransmit dedup) + `transitions.py` (STARTTLS/strip detection).
- `tls_parser.py`: record layer → ClientHello/ServerHello/Certificate/
  alerts; negotiated params, offered-vs-chosen ciphers, SNI, PFS.
- `certificates.py`: X.509 parse + chain + weak-key/sig/expiry checks.
- Unit tests: each scenario pcap asserts its exact expected rule set
  (golden files). Property tests for reassembly.
- **Gate:** `python -m app.pipeline <pcap>` prints correct sessions, TLS
  params, certs, and fired rules for every scenario.

### Phase 3 — Rules, ML, scoring (Week 3–4)
- `rules.py`: full rule table (backend.md §4.7) with weights, references,
  remediation text. `score.py`: session + scan scores, grades.
- `ml/`: label corpus with rule engine → train GBM classifier +
  IsolationForest offline → commit joblib models. `ml_runtime/`: predict +
  feature-z anomaly explanations.
- **Gate:** mixed pcap produces stable score/grade; anomalies flagged with
  human-readable "why"; classifier ≥ 0.95 on labeled corpus.

### Phase 4 — API + persistence (Week 4)
- All routers per backend.md §5; JWT verification; pipeline runner on
  `ThreadPoolExecutor` (202 + poll pattern); batch persistence; reports
  JSON/HTML/PDF; PCAP auto-deletion hook.
- Load sanity: 25 MB mixed pcap completes < 60 s, peak RAM < 350 MB.
- **Gate:** full API flow via curl/Postman: upload → analyze → poll →
  sessions/findings/certs/anomalies → all three report formats download.

### Phase 5 — Frontend (Week 4–5, overlaps Phase 3+)
- Weeks 4: App Shell + dashboard + upload wizard + status poller (fixture
  JSON until API ready), auth screens.
- Week 5: workspace tabs (Overview, Sessions, Findings, Certificates,
  Anomalies, Reports), session detail + handshake timeline, `/compare`,
  wire to live API, landing page per frontend.md §3.
- **Gate:** responsive pass at 320/375/414/768; cold-start UX verified
  against a sleeping Render service; a11y pass (keyboard-only run-through).

### Phase 6 — Hardening + pitch (Week 5–6)
- End-to-end rehersal on the deployed stack (not localhost). Keep-alive
  cron on `/health`. Fix cold-start, timeout, and RLS edge cases.
- Idea-pitch deck + demo video script: problem → live demo (upload scenario
  pcap → findings in ~30 s) → architecture → ML story (rules = certainty,
  ML = novelty) → compliance mapping → roadmap. No invented metrics; use
  real numbers from your corpus runs.
- **Gate:** fresh-URL demo completes in < 5 min including cold start;
  backup: pre-rendered reports + screen recording in case of live-demo
  failure.

---

## 3. Parallelization trick: fixture-first frontend

The backend team publishes `docs/ps/fixtures/*.json` (exports from Phase 2
runs over scenario pcaps) by end of Week 2. Frontend builds every screen
against fixtures with TanStack Query mocked — zero blocking on API
readiness, then swaps `apiFetch` to the live backend in Phase 5. This
decouples the two critical paths completely.

---

## 4. Risk register

| Risk | Likelihood | Mitigation |
| --- | --- | --- |
| TLS parser complexity blows the timeline | high | scope to ClientHello/ServerHello/Certificate/Alerts; TLS 1.3 sessions degrade gracefully ("encrypted handshake — parameters inferred") |
| Python/OpenSSL refuses ancient configs (TLS 1.0, RC4) on Windows | medium | generate those scenarios in Google Colab; pcaps are just files |
| Render cold start kills the live demo | high | keep-alive ping + "waking the engine" UI + pre-generated fallback reports |
| 512 MB RAM exceeded on big pcaps | medium | 25 MB cap, dpkt, bounded buffers, batch inserts, stage-boundary GC |
| Supabase pause / free-tier limits | low | keep-alive touches Postgres via `/health`; auto-delete pcaps after 24 h |
| Team member bandwidth (exams etc.) | medium | forensics core is the only hard-coupled path; phases 1–2 have buffer built in |

---

## 5. Deliverable → problem-statement trace

Every PS expected output maps to a spec location — use this table in the
pitch to prove full coverage:

| PS deliverable | Where |
| --- | --- |
| SMTP/IMAP/POP3 identification | backend.md §4.2 |
| STARTTLS detection + validation | §4.4 (+ downgrade/strip finding CFG-004) |
| TCP stream reconstruction | §4.3 |
| TLS handshake reconstruction, version, cipher, kex | §4.5 |
| X.509 extraction, chain, expiry, key/sig analysis | §4.6 |
| Weak crypto / deprecated TLS / insecure config | §4.7 rule table |
| Forward secrecy assessment | §4.7 PFS-001 |
| AI risk classification, anomaly detection, scoring, prioritization, recommendations | §4.9 + §4.7 + §4.10 |
| Forensic reports JSON/PDF/HTML | §4.11 |
| Interactive dashboard | frontend.md §4 |
| Synthetic dataset generation | backend.md `scripts/` (pure Python, no Docker) |
