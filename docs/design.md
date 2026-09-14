# Design — Prahari (SecureMailScope)

Locked design system for the Prahari (SecureMailScope) web application (SIH 2026 · PS 26159).
Future Hallmark runs read this file first; all pages defer to it. Amend
intentionally — the file is the rule.

```css
/* Hallmark · pre-emit critique: P4 H4 E4 S5 R5 V4
 * genre: atmospheric · macrostructure: Workbench (landing) + App Shell (product)
 * theme: Midnight · axes: dark-paper / sans-display / cool-cyan accent
 * nav: N5 floating pill (landing) + N3 side-rail (app) · footer: Ft5 statement
 * motion: fade-in · score-counter · scan-pulse · reduced-motion ≤150ms crossfade
 */
```

Inferred design context (redirect if wrong): **audience** = SOC analysts, forensic
investigators, enterprise admins, SIH judges · **use case** = upload a PCAP → read a
cryptographic posture score → drill into sessions, certificates, findings → export
reports · **tone** = technical — an instrument, not a brochure.

## System

- Genre · **atmospheric** (dark technical tool; the "instrument you use after dark")
- Macrostructure · **Workbench** for the public landing (guided tour of the app in use) · **App Shell** for the product itself
- Theme · catalog **Midnight** (atmospheric cluster)
- Axes · dark paper (L ≈ 15 %) / weighty sans display / cool cyan accent
- Nav · landing: **N5 floating pill** (blur over the dark canvas) · app: **N3 side-rail** sidebar
- Footer · **Ft5 statement** (landing only; the app has no footer)

## Product surfaces

| Surface | Purpose | Layout |
| --- | --- | --- |
| `/` landing | pitch the tool to judges/visitors | Workbench: hero statement, real screenshots in `<figure>` hairline frames, capability list, pipeline diagram, closing statement footer |
| `/login`, `/register` | Supabase auth | single centred card on bare canvas |
| `/dashboard` | scan history, score trends | stat strip + scan table |
| `/scans/new` | upload + start analysis | centred dropzone wizard |
| `/scans/[id]` + tabs | the instrument: overview, sessions, findings, certificates, anomalies, reports | App Shell: side-rail + tabbed content |
| `/scans/[id]/sessions/[sid]` | one session forensically: handshake timeline, negotiated params, cert | detail column, max 75ch measure for prose blocks |
| `/compare` | scan-to-scan diff | two-column split |

## Tokens (canonical · `tokens.css` is the source of truth)

```css
:root {
  /* paper — elevation rises toward the user, +3% L per level */
  --color-paper:      oklch(15% 0.012 255);
  --color-paper-2:    oklch(18% 0.014 255);   /* cards, raised panels */
  --color-paper-3:    oklch(22% 0.016 255);   /* hover surfaces, popovers */
  --color-rule:       oklch(30% 0.014 255);   /* dividers, table rules */
  --color-ink:        oklch(93% 0.006 250);   /* primary text */
  --color-neutral:    oklch(62% 0.010 255);   /* secondary text, placeholders */
  --color-muted:      oklch(45% 0.010 255);   /* disabled text only */
  --color-accent:     oklch(80% 0.120 195);   /* phosphor cyan */
  --color-accent-ink: oklch(18% 0.030 195);   /* text on accent fills */
  --color-focus:      oklch(80% 0.140 195);

  /* semantic severity — data meaning, never decoration */
  --color-critical:    oklch(64% 0.190 25);
  --color-high:        oklch(72% 0.150 55);
  --color-medium:      oklch(80% 0.140 95);
  --color-low:         oklch(75% 0.110 230);
  --color-pass:        oklch(75% 0.130 150);
  /* opaque badge fills (no alpha-defined colours) */
  --color-critical-bg: oklch(25% 0.050 25);
  --color-high-bg:     oklch(26% 0.045 55);
  --color-medium-bg:   oklch(27% 0.045 95);
  --color-low-bg:      oklch(26% 0.040 230);
  --color-pass-bg:     oklch(26% 0.045 150);
  /* grade scale reuses severity hues: A=pass B=low C=medium D=high F=critical */

  --font-display: "Geist", ui-sans-serif, system-ui, sans-serif;  /* 600, -0.03em */
  --font-body:    "Geist", ui-sans-serif, system-ui, sans-serif;  /* 350–400 */
  --font-mono:    "JetBrains Mono", ui-monospace, monospace;      /* data register */

  /* 4-pt spacing scale: --space-3xs 2 · 2xs 4 · xs 8 · sm 12 · md 16
     lg 24 · xl 32 · 2xl 48 · 3xl 64 · 4xl 96                              */
  /* Type scale, 1.25 ratio: --text-xs .8rem (table meta/badges only) ·
     --text-base 1rem · --text-md 1.25rem · --text-lg 1.5625rem ·
     --text-xl 1.9531rem · --text-2xl 2.4414rem · --text-3xl 3.0518rem ·
     --text-display clamp(2.75rem, 5vw + 1rem, 5.25rem) landing only        */

  --ease-out:   cubic-bezier(0.16, 1, 0.3, 1);
  --ease-in-out: cubic-bezier(0.65, 0, 0.35, 1);
  --dur-fast: 180ms;  --dur-base: 240ms;  --dur-slow: 320ms;

  --radius-card: 10px;  --radius-input: 8px;  --radius-pill: 999px;
}
```

Discipline:

- **One accent.** Cyan marks active nav, links, focus rings, primary CTA, and the
  score dial needle — ≤ 3 % of any viewport. Severity colours are *data*, used only
  where severity is the content (badges, finding rows, charts).
- **Mono has one role:** technical data — cipher suites, serials, fingerprints,
  hashes, IPs, the wordmark. Body copy is never mono.
- **No pure black/white**, no flat grey, no gradients other than the single
  atmospheric bloom on the landing canvas (one radial bloom, ~25 % footprint,
  fixed, unanimated; **none** on data screens — charts must read clean).
- **No glassmorphism, no glow text, no gradient text.** Elevated `paper-2/3`
  cards replace hairline-on-paper; `--color-rule` appears only as 1px table and
  divider lines.

## App Shell (N3 side-rail)

- Fixed left rail, 240px desktop / icon-only 56px ≤ 768px / bottom tab bar ≤ 480px.
- Rail sections: *Scans* (Dashboard, New Scan, History, Compare) · *Active scan*
  (Overview, Sessions, Findings, Certificates, Anomalies, Reports — contextual)
  · *Account*. Active item: accent text + 2px accent left-edge marker (never a
  filled block).
- Content column max-width 1200px; prose blocks capped at 65ch.

## Core components

| Component | Spec |
| --- | --- |
| **ScoreDial** | SVG arc 0–100, grade letter (A–F) centred in Geist 600, arc + letter in the grade's severity hue; count-up animation 600ms once |
| **SeverityBadge** | pill, opaque `*-bg` fill + severity text, uppercase mono 12.8px 0.08em tracking; always carries the word (CRITICAL…) — colour is never the only signal |
| **FindingRow** | severity badge · title (Geist 600) · rule id + reference tag (mono) · expandable evidence block (mono, pre-wrap) · recommendation sentence |
| **SessionTable** | dense table, 12.8–14px, tabular-nums; columns: time, proto tag, src→dst, TLS ver, cipher (mono), PFS icon, grade chip; row = link |
| **CertCard** | subject/issuer, validity bar (issued→expiry with marker at today), key + sig algorithm chips, fingerprint in mono |
| **HandshakeTimeline** | vertical timeline of TLS messages; STARTTLS transition marked with an accent edge label |
| **StatCard** | label (small caps) · value (tabular-nums) · delta vs previous scan |
| **UploadDropzone** | dashed rule border, hover paper-3, drag accent border, progress bar + stage list during analysis |
| **EmptyState** | one sentence + one action; no illustrations |

All interactive components ship the full eight states (default · hover ·
focus-visible · active · disabled · loading · error · success). Focus rings show
instantly (never animated) at ≥ 3:1 contrast.

## CTA voice

- Primary · `--color-accent` fill · `--color-accent-ink` text · `--radius-pill` ·
  padding `--space-sm --space-lg` · Geist 600. Used once per view ("Upload PCAP",
  "Run analysis", "Download report").
- Secondary · 1px `--color-rule` outline, `--color-ink` text, same radius.
- No ghost-on-accent, no double primary, no gradient buttons.

## Motion stance

- Three primitives, no more: **fade-up reveal** on page content (once, 240ms,
  8px translate, `--ease-out`) · **score count-up** (600ms) · **scan pulse** —
  the analysis progress bar's functional pulse. Toasts are silent-success;
  destructive actions use optimistic update + Undo, never confirm dialogs.
- `prefers-reduced-motion: reduce` → every spatial motion collapses to a
  ≤ 150ms opacity crossfade; the progress bar becomes static.

## Copy voice

- Plain, specific, analyst-grade: "TLS 1.0 negotiated on imap.corp.example:143 —
  prohibited by NIST SP 800-52r2." No marketing adjectives inside the product.
- Landing voice, atmospheric register: short declaratives. *"Read the wire, not
  the docs."* · *"Passive by design. The mail keeps flowing."*
- Real numbers only. Where a metric isn't real yet, show `—` with a labelled
  placeholder block — never an invented stat.

## Accessibility

- Body ≥ 16px; table meta ≥ 12.8px; nothing below 10px. Placeholder text uses
  `--color-neutral` (4.5:1); `--color-muted` is disabled-only.
- Every chart has a table or text alternative. Severity always carries text +
  icon, never colour alone (colour-blind safe by design).
- Full keyboard path through the app; visible focus everywhere; `aria-live` on
  scan status changes.
- Verified at 320 / 375 / 414 / 768px: no horizontal scroll (`overflow-x: clip`
  on html+body), tables collapse to stacked cards ≤ 768px, no two-line
  clickable text, image/grid tracks use `minmax(0, 1fr)`, display headers wrap
  via `overflow-wrap: anywhere; min-width: 0`.

## Anti-patterns (banned outright)

Italic headers · gradient text · purple-cyan gradients · section eyebrow
numbers/tags (except genuine ordinal pipeline steps on the landing, max 2,
stacked above headings — never left-margin hanging labels) · re-drawn fake
browser/terminal chrome around screenshots (real screenshots in `<figure>` +
hairline) · glassmorphism · invented metrics/testimonials/logo walls · accent
fills beyond small CTA/badge surfaces · mono body copy · toasts celebrating
routine successes.

## Exports

`frontend/tokens.css` is the source of truth (inside the Vercel root directory). The Next.js app maps these
tokens into its Tailwind theme (see `frontend.md` § Design tokens). For DTCG
`tokens.json` or shadcn/ui CSS variables, extend this file later — do not fork
the palette per-page.
