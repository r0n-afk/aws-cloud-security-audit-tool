# User Interface Design — AWS Cloud Security Audit Tool

**Version:** 1.0  
**Design law:** aura-farming constraints (no purple gradients, no emoji bullets, no identical card grids, no filler copy)  
**Aesthetic direction:** **Locked (P5 provisional — pending final visual go/no-go): forensic audit dossier.**
Bone-white paper `#f7f5f0`, ink chrome `#111418`, one signal-red accent `#c8102e`.
Type: Archivo (UI) + IBM Plex Mono (numbers, ARNs, tables). Hairline rules, Swiss grid, radius 0.
Signature motif: asymmetric `dossier-hero` score block + hairline `severity-strip` (not identical cards).
Sidebar (left ink rail) confirmed; light+dark both supported; dashboard keeps typographic hero (no gauge).

---

## 1. Design constraints (binding)

1. **No purple/blue gradient hero blobs** or generic “AI SaaS” chrome.
2. **No emoji as bullets, icons, or status markers** in the product UI.
3. **No identical rounded-card grid** as the default layout — use tables, split panes, dossier headers, or asymmetric composition where content allows.
4. **No filler copy** (“Welcome to your dashboard!”, “Supercharge your security”) — labels state facts and numbers.
5. Severity must not rely on **color alone** — include text label always (accessibility).
6. Works offline / localhost. Direction locked → webfonts may load from Google Fonts CDN (Archivo + IBM Plex Mono) with system fallbacks so core UI still works offline.
7. Aura gate runs before ship (P4): screenshot review against the banned list.

---

## 2. Information architecture

```text
[ Auth wall ] setup · login
        │
        ▼
[ Shell — base.html ]
  Sidebar / top nav
    Dashboard
    Assessments (New · Detail)
    Findings
    Reports
    History
    Comparison
    Remediation
    Settings
  + identity (user, logout) · mode badge (aws|demo) · AI indicator (if on)
        │
        ▼
Module screens (below)
```

One `base.html` owns shell chrome; module templates extend it.

---

## 3. Screens

### 3.1 Auth — Setup (`auth/setup.html`)

- **Purpose:** create the single local account on first run.
- **Layout:** centered single column, max-width ~24rem; form fields username, password, confirm; primary action.
- **States:** validation errors inline (short password, mismatch); success → redirect login.

### 3.2 Auth — Login (`auth/login.html`)

- Same shell language as setup (visual pairing).
- Fields: username, password; error line for invalid credentials; no “remember me” (v1).

### 3.3 Dashboard (`dashboard/index.html`)

- **Hero metric:** latest security score (large numeral, out of 100) — the one display-scale element.
- **Adjacent strip:** total findings, critical count, last scan date/status (inline stats, not 4 identical cards).
- **Severity breakdown:** horizontal bar or compact stacked row with text counts.
- **Quick actions:** Start assessment · View findings · Generate report (text buttons, distinct weight).
- **Recent assessments:** compact table (name, date, score, status) — not a card grid.
- **Empty state:** factual — “No assessments yet” + one action.

### 3.4 New assessment (`assessment/new.html`)

- Single form: name (required), description (optional).
- Assessment new form shows the current scan mode banner (AWS or demo catalog) without exposing mode controls.
- Primary: Run assessment. Secondary: Cancel.
- On AWS mode, helper text mentions credential expectation (hard error if missing — copy links to error message).

### 3.5 Assessment detail (`assessment/detail.html`)

- **Header dossier:** name, date, status badge, score, engines used, `raw → deduped` counts (redundancy proof), scan_error banner if failed.
- **Severity row:** five counts with text labels.
- **Actions:** Generate report · Compare · (AI prioritize if enabled).
- **Findings preview:** first N rows + link to full Findings screen.

### 3.6 Findings (`findings/index.html`)

- **Controls row:** search input, severity filter, status/remediation filter, sort control.
- **Table:** severity (badge + label), title, category, resource (truncated ARN), engines, remediation status, actions.
- **Optional AI Q&A box** (only rendered when AI on): question field + ask; answer panel uses escaped text only.
- Pagination if large.

### 3.7 Finding detail (`findings/detail.html`)

- Two-column on wide: main (title, severity, category, control id, resource, description) + side (remediation status control, recommendation, engines provenance).
- **AI advice panel:** button when AI on → panel below recommendation (client posts with CSRF header).
- Breadcrumbs: Findings → detail.

### 3.8 Reports (`reports/index.html`)

- Generate form: assessment select, format select (HTML/PDF/JSON).
- PDF note if WeasyPrint unavailable (shown as inline hint, not a modal scare).
- Table of past reports: type, date, download action.
- Path/id tampering → error template.

### 3.9 History (`history/index.html`, `history/detail.html`)

- Index: reverse-chronological table of assessments (score, findings, engines, status).
- Detail: read-only snapshot reusing assessment detail patterns + link to generate report.

### 3.10 Comparison (`comparison/index.html`)

- Two selects (assessment A / B) → side-by-side metrics: score, total, severity counts, delta arrows as text (`+3 critical` / `−2 medium`).
- No decorative chart dependency required for v1; numeric deltas carry the story.

### 3.11 Remediation (`remediation/index.html`)

- Board/table grouped or filterable by remediation status: open · in progress · remediated · accepted.
- Inline status change actions (POST + CSRF).

### 3.12 Settings (`settings/index.html`)

- Sections: Appearance (theme) · Report format · AI (enable checkbox + hidden respect for unchecked, base URL, masked API key, model, rate limits display) · Danger/reset notes (text link to docs).
- Sensitive fields never re-display raw values after save.

### 3.13 Errors (`errors/404.html`, `errors/500.html`)

- Plain factual message + link home; no stack traces.

---

## 4. Layout system (locked)

| Token | Locked value |
|-------|-------------|
| Max content width | 1200px |
| Nav | Left ink sidebar (232px), mobile off-canvas |
| Spacing scale | 4 / 8 / 12 / 16 / 24 / 32 / 48 |
| Radius | 0 (hard corners) |
| Type scale | Body 14px UI; mono data 10–12px; display score 72px dashboard hero only |
| Elevation | 1px hairline borders only — no drop shadows |
| Status colors | Semantic + **always** text label (mono uppercase badges) |

---

## 5. Components inventory

- Stat/hero score block (dashboard)
- Severity badge (5 levels, text+color)
- Status pill (assessment status, remediation status)
- Data table (sortable headers client-side where cheap)
- Form controls: text, password, select, checkbox, textarea
- Primary / secondary / danger buttons
- Alert banner (scan_error, AI disabled hints)
- Modal: **avoid** in v1; inline expanders preferred
- Loading: disable submit + button label change (no spinner dependency required)

---

## 6. Accessibility bar

- Contrast ≥ WCAG AA for body text and controls.
- Keyboard reachable: nav, tables, forms, AI buttons.
- Focus visible (do not remove outlines without replacement).
- Severity/status never color-only.
- Form errors associated with inputs (`aria` or visible text adjacent).

---

## 7. Open decisions (P5 — owner lock)

- [x] Aesthetic direction → **forensic audit dossier** (bone/ink/signal-red, Archivo + IBM Plex Mono, radius 0, hairline rules)
- [x] Sidebar vs top nav → **left ink sidebar** (collapsible on mobile)
- [x] Light only vs light+dark → **light + dark** (theme toggle already wired)
- [x] Dashboard distinctive viz → **typographic hero + hairline strips**; charts use ink/red palette only (no gauge)

*Remaining P5 gates: final screenshot go/no-go, LICENSE content, git commit commands (user-run).*
