# Frontend — Prahari (SecureMailScope)

Complete frontend specification. The visual language is locked in
[`design.md`](design.md) with canonical values in [`frontend/tokens.css`](../frontend/tokens.css)
— read those first; this document covers everything else: stack, routes,
components, data flow, and quality bars.

Two-surface system: light marketing canvas for the landing/auth pages
(`.theme-light`), dark instrument theme for the console. Space Grotesk +
DM Mono. Motion via `motion` v13 with `useReducedMotion` respected
everywhere.

---

## 1. Stack

| Concern | Choice | Why |
| --- | --- | --- |
| Framework | **Next.js 15 (App Router) + TypeScript** | Vercel-native, zero config on hobby plan |
| Styling | **Tailwind CSS v4** with the design tokens mapped into `@theme` | no runtime CSS, fast |
| Charts | **Recharts** | simple, table-friendly, no canvas heavyweights |
| Data | **TanStack Query v5** | polling, caching, retries — built for scan status |
| Auth | `@supabase/ssr` (session only) | cookie session; all data still via our API |
| Icons | `@phosphor-icons/react` (ssr imports) | consistent icons, tree-shaken |
| State | server state = TanStack Query; local UI state = React | no Redux needed at this scope |
| PDF/exports | backend-generated; frontend just downloads | single source of truth |

Fonts: **Geist** (display + body) and **JetBrains Mono** (data outlier) via
`next/font/google` with `display: swap` and metric-matched fallbacks.
Tabular numerals (`font-variant-numeric: tabular-nums`) on every numeric
column, stat, and score.

---

## 2. Route map

```
/                        Landing (Workbench macrostructure, public)
/login                   Login (email + password, demo-analyst button)
/signup                  Signup (strength meter, verification-sent state)
/forgot-password         Request a reset link
/reset-password          Set a new password (via reset link)
/auth/callback           Supabase code-exchange route handler
/auth/confirm            Legacy token-flow confirmation forwarder
/(app)/dashboard         Scan history + score trend + stat strip
/(app)/scans/new         Upload wizard (drag-drop, stage list)
/(app)/scans/[id]        Scan workspace, tabbed (see §4)
/(app)/scans/[id]/sessions/[sid]   Session detail
/(app)/compare           Scan-to-scan diff (pick two scans)
/(app)/settings          Account, deployment info, model card
```

Route groups: `(app)` shares the App Shell layout (N3 side-rail + top bar).
Public routes share the landing layout (N5 floating pill nav, Ft5 footer).
Auth routes are bare-canvas centred cards.

---

## 3. Landing page (`/`) — Workbench macrostructure

A guided tour of the instrument in use, not a marketing page. Sections:

1. **Hero** — short declarative display line (≤ 7 words), one supporting
   sentence, primary CTA "Open the console" + secondary "How it works".
   Single radial bloom on the canvas behind the hero (fixed, unanimated).
   Nav: N5 floating pill (blur over the bloom).
2. **Pipeline strip** — the forensic pipeline as a horizontal 12-stage
   diagram (PCAP → protocol ID → TCP reassembly → STARTTLS → TLS parse →
   certs → rules → ML → score → reports). Genuine ordinal steps only; drawn
   as one SVG diagram, no card grid.
3. **Workbench tour** — 3–4 real product screenshots in `<figure>` with a
   hairline border (overview score dial, findings table, certificate
   inspector, anomaly view). Real screenshots from the actual app —
   **no fake browser chrome, no mockups**. Each figure gets one caption
   sentence, alternating text/image sides.
4. **Capabilities** — the PS deliverables mapped to features, as a compact
   two-column definition list (term + one sentence), not a 6-card icon grid.
5. **Statement close** — Ft5 footer: one bold sentence ("Read the wire, not
   the docs."), minimal links, team credit line. No link-column footer.

Copy voice: plain analyst-grade declaratives. Real numbers only — the live
stats endpoint feeds any counter; until scans exist show `—` placeholders
(labelled), never invented metrics.

---

## 4. Scan workspace (`/scans/[id]`) — the instrument

App Shell: fixed left side-rail (nav per design.md § App Shell) + content
column. Top of the workspace: scan header — name, file meta, **ScoreDial**
(0–100 + grade letter), protocol count chips, status line. Below: tabs.

| Tab | Content |
| --- | --- |
| **Overview** | ScoreDial, findings-by-severity bar, PQC/credential stat cards, **AI layer card** (anomalous count, ML risk distribution, rule → adjustment → fused breakdown), top 5 findings, executive summary |
| **Sessions** | dense table: session id, proto tag, server, TLS version, cipher (mono), PFS icon, **ML risk chip + anomaly flag**, grade chip, reassembly-gap marker. Filter: transport. Row → session detail |
| **Findings** | grouped by severity (critical first), each a `FindingRow`: badge, title, rule id + reference tag, expandable evidence (mono JSON), remediation text, affected-session count. Filters by category |
| **Certificates** | `CertCard` grid: subject/issuer, validity bar (issued → expiry with today-marker), key + signature chips, chain-issues list, fingerprint (mono, copy button), "View PEM" drawer with the actual X.509 |
| **Anomalies** | IsolationForest-flagged sessions; each row shows score + "why" — top deviant features as plain sentences ("TLS version 3.1σ below baseline") |
| **Compliance** | findings grouped by standard + clause (NIST 800-52r2 / RFC 8996 / BSI / CERT-In / FIPS 203-205) with per-control pass/fail — answers "which clause failed?" |
| **Reports** | three export cards (JSON / HTML / PDF) with generate + download; PDF preview thumbnail |

**Session detail** (`/scans/[id]/sessions/[sid]`): handshake parameters
panel (version, suite, kex, PFS), **HandshakeTimeline**, **AI assessment
panel** (risk class + probabilities, anomaly score, rule → fused breakdown,
"why this was flagged" z-score list), reassembly-gap notice, cleartext
credentials (redacted), pcap frame evidence, findings affecting this
session with per-session score.

---

## 5. Core components (inventory)

Design specs in design.md § Core components. Implementation notes:

| Component | Implementation notes |
| --- | --- |
| `ScoreDial` | SVG arc, stroke-dashoffset animation, count-up 600ms once on mount; grade letter inside; hue = severity mapping |
| `SeverityBadge` | opaque `--color-*-bg` + `--color-*` text, uppercase mono `--text-xs`; always includes the word |
| `FindingRow` | disclosure (`<details>`-like a11y pattern), evidence in `<pre>` mono with copy button |
| `SessionTable` | CSS table + sticky header; ≤ 768px rows become stacked cards (design.md responsive rules); `minmax(0, 1fr)` grid tracks |
| `CertCard` | validity bar = simple positioned divs; expiry within 30d shows LOW badge |
| `HandshakeTimeline` | vertical `<ol>`, accent edge on STARTTLS step, alert steps in severity color + icon |
| `StatCard` | small-caps label + tabular-nums value + delta arrow vs previous scan |
| `UploadDropzone` | drag state (accent border), validation errors inline (magic bytes, size), upload → analyze → progress stage list, all 8 states |
| `EmptyState` | one sentence + one action; first-run dashboard teaches the upload flow |
| `ScanStatusPoller` | TanStack Query `refetchInterval: 2000` while status ∈ {queued…reporting}; renders stage + progress; on `failed` shows error + retry |
| `GradeChip` | A–F, severity-hued, used in tables everywhere |
| `CopyButton` | silent success (icon swap 1.5s), never a toast |

Every interactive element ships all eight states (default · hover ·
focus-visible · active · disabled · loading · error · success) per
design.md. Focus rings instant, never animated.

---

## 6. Data flow & API integration

- **One API boundary**: every fetch goes through `api()` in `lib/api.ts`
  which attaches `Authorization: Bearer <token>` (Supabase access token in
  cookie-session mode, `dev-<user>` in local mode). No direct Postgres
  access from the client.
- **Auth**: `@supabase/ssr` browser client (cookie session) +
  `middleware.ts` that refreshes the session on every request and guards
  the `(app)` group (`/login?next=<path>` when unauthenticated). On a 401
  the client attempts one silent refresh, then dispatches
  `prahari:session-expired` → toast ("Your session expired") + redirect.
  Local/demo mode bypasses all of it (offline demos must work).
- **TanStack Query keys**: `['scans']`, `['scan', id]`,
  `['scan', id, 'sessions', filters]`, … — tab switches and back-navigation
  are instant from cache.
- **Upload → analyze → poll** flow: `POST /scans` (multipart, with
  `onUploadProgress`) → `POST /scans/{id}/analyze` (202) → poll
  `GET /scans/{id}/status` every 2 s → on `complete`, invalidate
  `['scan', id]` and route to the Overview tab. Upload UX shows the stage
  list from design.md; backend stages map 1:1 to the pipeline stages in
  backend.md §4.
- **Cold start handling**: on network error/timeout to `/health`-backed
  routes, show "Waking the analysis engine — this takes about a minute on
  first load" with a spinner and auto-retry (5 attempts, backoff). Never a
  raw browser error page — judges will hit this.
- **Error contract**: `{detail}` toast-less inline errors near their
  trigger; destructive actions (delete scan) use optimistic update + Undo
  banner, no confirm dialogs.
- **`/compare`**: two scan pickers → diff view: score delta, findings added/
  resolved between scans, per-server grade changes. Data from two parallel
  `['scan', id]` queries, diff computed client-side.

---

## 7. Design-token mapping (Tailwind v4)

`globals.css` imports `tokens.css` values into Tailwind's `@theme` so
utilities carry the system:

```css
@import "../tokens.css";   /* frontend/tokens.css — canonical */

@theme inline {
  --color-paper:  var(--color-paper);
  --color-surface: var(--color-paper-2);
  --color-raised: var(--color-paper-3);
  --color-line:   var(--color-rule);
  --color-ink:    var(--color-ink);
  --color-subtle: var(--color-neutral);
  --color-accent: var(--color-accent);
  --color-critical: var(--color-critical);
  --color-high:     var(--color-high);
  --color-medium:   var(--color-medium);
  --color-low:      var(--color-low);
  --color-pass:     var(--color-pass);

  --font-sans: var(--font-body);
  --font-mono: var(--font-mono);

  --spacing: 0.25rem;               /* 4-pt base */
  --radius-card: 10px;
  --ease-out-quart: cubic-bezier(0.16, 1, 0.3, 1);
}
```

Rules: no raw hex/oklch in components — tokens only (design.md § Tokens);
severity colors appear only where severity is the content; the cyan accent
stays under ~3% of any viewport; no gradients outside the single landing
bloom.

---

## 8. Folder structure

```
frontend/
├─ app/
│  ├─ page.tsx                  # landing
│  ├─ login/ · register/
│  ├─ (app)/
│  │  ├─ layout.tsx             # App Shell (side-rail)
│  │  ├─ dashboard/page.tsx
│  │  ├─ scans/new/page.tsx
│  │  ├─ scans/[id]/page.tsx    # workspace + tabs
│  │  ├─ scans/[id]/sessions/[sid]/page.tsx
│  │  └─ compare/page.tsx
│  └─ globals.css               # @theme mapping (§7)
├─ middleware.ts               # Supabase session refresh + route guard
├─ components/                  # flat: ui.tsx, motion.tsx, ScoreDial,
│                               # PostureTrend, HandshakeTimeline,
│                               # EvidenceHex, Toast.tsx
├─ lib/
│  ├─ api.ts                    # api() client, token mode, wake retry, 401 refresh
│  ├─ supabase.ts               # browser client (@supabase/ssr)
│  ├─ supabase.server.ts        # server client (route handlers)
│  ├─ types.ts                  # API response types (mirrors backend.md §5)
│  └─ visuals.ts                # bytes, durations, severity hues
└─ tokens.css                   # canonical (frontend/ is self-contained for Vercel)
```

---

## 9. Quality bars (definition of done)

- **Responsive**: verified at 320 / 375 / 414 / 768 px. No horizontal scroll
  (`overflow-x: clip` on html+body); SessionTable and Findings collapse to
  stacked cards ≤ 768px; side-rail → icon rail ≤ 768px → bottom tabs
  ≤ 480px; no two-line clickable text anywhere.
- **A11y**: keyboard-complete path; visible focus ≥ 3:1; severity always
  text + icon (never colour alone); every chart has a data-table
  alternative; `aria-live="polite"` on scan status; contrast per design.md.
- **Performance**: landing LCP < 2.5s (no heavy assets; screenshots
  AVIF/WebP, `next/image`, lazy below fold); workspace tabs code-split;
  tables virtualized past 200 rows; no client-side data lib > 50 KB gz.
- **Motion**: the three primitives only (fade-up reveal, score count-up,
  progress pulse); `prefers-reduced-motion` → ≤ 150ms opacity crossfades.
- **Honesty**: zero invented metrics; placeholders are `—` with labels.
