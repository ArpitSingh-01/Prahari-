# Prahari — 5-minute demo script (SIH 2026, PS 26159 NTRO)

*Prahari — SecureMailScope · AI-Assisted Cryptographic Security Posture
Assessment.* The beats below are ordered for a stage run: one upload, one
drill-down, one export, one flip. Total: ~5 minutes including cold-start.

Before the stage (do once, not live):
- Deploy stack is up; engine pinged warm (cron-job.org `/api/health` every
  10 min). If the judge slot is the first of the day, trigger the health
  ping 2 minutes early.
- Browser: two tabs — the console, and a file manager with
  `mixed.pcap` and `after-remediation.pcap` ready.
- Signed in as the demo analyst (or use "Continue as demo analyst" in
  local mode).

## 1. The one-liner + landing (30s)

> "Prahari is a passive forensic sentinel for email cryptography: we upload
> a capture of SMTP, IMAP or POP3 traffic, and it reconstructs every
> session, parses every TLS handshake, checks every certificate, and
> scores the cryptographic posture 0–100 — mapped to NIST 800-52r2, BSI
> TR-02102 and CERT-In, with an AI layer whose influence is bounded and
> published. Nothing is ever sent to a mail server; the mail keeps flowing
> while we look."

Point at the landing counters (real `/api/stats` numbers — say so) and the
pipeline strip.

## 2. Upload an unseen capture (60s — this is the <60s score promise)

- Dashboard → **New scan** → drag `mixed.pcap` (10 "unseen" sessions:
  cleartext auth, TLS 1.0+RC4, expired cert, STARTTLS stripped, ...).
- The stage list shows upload → wake → reassembly → handshakes → scoring.
- If the engine was asleep: the UI explicitly says "waking the analysis
  engine" and retries — point at it, it's a free-tier feature, not a bug.

## 3. Read the verdict (60s)

- Scan overview: **score dial** animates in (~grade F). Executive summary
  sentences.
- **AI layer card**: anomalous sessions, ML risk distribution, and the
  `rule → AI-adjusted → fused` breakdown. Say the one-liner: "The AI can
  only deepen a verdict the rules already imply — at most 10 points on the
  whole scan — and a clean capture stays exactly 100."
- Findings tab: sorted critical→low. Everything names its rule ID, its
  NIST/CERT-In clause, its remediation, and links to wire evidence.

## 4. Evidence drill-down — the "not a tshark wrapper" beat (60s)

- Findings → **TLS 1.0 negotiated** → expand: frame numbers + the actual
  server bytes.
- Click into the session: **handshake timeline**, TLS version, RC4 cipher
  suite, offered-vs-chosen ciphers.
- Back to Findings → **Cleartext credentials observed** (CRE-001): note
  "credentials redacted" — the password never leaves the capture. The
  hex window shows the AUTH LOGIN exchange with redacted fields.

## 5. Compliance view (30s)

- **Compliance tab**: findings grouped by standard and clause —
  "which NIST control failed?" answered directly. Mention the same
  mapping ships as an appendix table in every PDF/HTML report.

## 6. Export the PDF (30s)

- **Reports tab** → PDF. Scroll: score + fusion line, findings with
  references, session inventory with ML column, AI anomaly analysis with
  z-score narratives, certificate inventory, compliance appendix, and the
  fusion-method paragraph. "This is the artifact an auditor keeps."

## 7. The remediation flip — the money beat (60s)

- **Compare** tab (or scan list): baseline = `mixed.pcap`, comparison =
  `after-remediation.pcap`.
- The same servers, fixed: TLS 1.2/1.3 everywhere, no cleartext, good
  certs. Grade chip flips F → **A**, "+N points improved", findings list
  collapses to "resolved" with zero new ones.
- > "One capture told them what was broken and by which clause; the second
  proves the fix. That loop is the product."

## 8. Model card + honesty (30s)

- **Settings → Model card**: model types, feature count, train/test sizes,
  per-class F1, confusion matrix, IsolationForest flag rates on the clean
  baseline. Read the disclosure: "trained on rule-engine labels over a
  synthetic corpus; the anomaly detector learns an unsupervised healthy
  baseline."
- If asked about limitations: TLS 1.3 encrypts certificates (we show
  handshake params, no chain), no passive trust anchor (chain signatures +
  validity + SNI only), synthetic ML corpus — all stated in the UI and
  reports, never faked.

## Judges' likely questions — one-line answers

- **"How does the AI change the number?"** Bounded negative-only
  adjustment: ≤2 points per session, ≤10 per scan, anomaly-flag ×
  bad-class confidence; clean captures stay exactly 100/A. Formula is in
  every report appendix.
- **"Is it really passive?"** No packets are ever emitted; upload a pcap,
  read a verdict. The engine never opens a socket toward your mail
  servers.
- **"Where do the numbers come from?"** The deterministic rule engine
  (25 rules mapped to NIST 800-52r2 / RFC 8996 / BSI TR-02102 / CERT-In);
  the AI augments, it never replaces.
- **"What about TLS 1.3?"** Handshake parameters and ALPN are visible;
  the certificate is encrypted after ServerHello — we say so on the
  session page rather than guessing.
