# System Architecture — AWS Cloud Security Audit Tool

**Version:** 1.0

---

## 1. Overview

Local Flask monolith with a clear layered split: **UI (blueprints/templates) → services → engines (scanner) / analyzer / AI / reports → SQLite**. External scanners are isolated subprocess boundaries; the web process never runs scanner code in-process when Prowler/ScoutSuite are used.

```text
Browser (127.0.0.1:5000)
        │  HTTP + session cookie + CSRF
        ▼
┌──────────────────────────────────────────────┐
│  Flask app (src/app)                        │
│  ┌────────┐ ┌──────────┐ ┌───────────────┐   │
│  │ auth   │ │ assessment│ │ findings     │   │
│  │ dash   │ │ reports   │ │ comparison   │   │
│  │ history│ │ remediate │ │ settings · ai│   │
│  └────────┘ └────┬─────┘ └──────┬────────┘   │
│        before_request auth wall│            │
└────────────────────────────────┼────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                  ▼
      src/scanner          src/analyzer        src/ai
   orchestrator.py       normalize/dedupe     client.py
   prowler_engine        score/prioritize     rate_limit.py
   scoutsuite_engine                           │
   aws_checks (boto3)                           ▼
                      src/reports        OpenAI-compatible
        │              render.py          endpoint (HTTPS)
        ▼              HTML/PDF/JSON
  subprocess / boto3
  (Prowler, ScoutSuite)
        │
        ▼
   instance/csa_tool.db  ·  instance/reports/
```

---

## 2. Components

| Layer | Location | Responsibility |
|-------|----------|----------------|
| Entrypoint | `run.py` | Adds `src/` to `sys.path`, creates app, runs dev server on 127.0.0.1 |
| Config | `config.py` | Config classes; instance-persisted `SECRET_KEY`; cookie flags; rate-limit defaults |
| App factory | `src/app/__init__.py` | Extensions, blueprints, context processor, auth wall, error handlers, schema init |
| Auth | `modules/auth` | First-run setup, login, logout, brute-force delay, audit events |
| Assessment | `modules/assessment` | Create/run assessments; persist status, counts, engines, errors |
| Findings | `modules/findings` | List/detail, search/filter/sort |
| Reports | `modules/reports` + `src/reports` | Generate/download HTML·PDF·JSON; traversal guard |
| Comparison / History | respective modules | Trend + side-by-side; archive views |
| Remediation | `modules/remediation` | Status updates across findings |
| Settings | `modules/settings` | Theme, report format, AI config (masked secrets), limits |
| AI routes | `modules/ai` | remediate / prioritize / qna endpoints (feature-flagged) |
| Orchestrator | `src/scanner/orchestrator.py` | Creds probe → dual engines → boto3 fallback |
| Engines | `prowler_engine`, `scoutsuite_engine`, `aws_checks` | Produce raw finding dicts |
| Analyzer | `src/analyzer` | Normalize severity, dedupe (key = control+resource), score, prioritize |
| AI client | `src/ai` | OpenAI-compatible chat; rate limiter (min/day/concurrent) |
| Renderer | `src/reports/render.py` | Dossier-style HTML; WeasyPrint PDF optional; JSON dump |

---

## 3. Scan pipeline

```text
POST /assessment/create
        │
        ▼
run_assessment()
        │  status = running
        ▼
orchestrator.run_scan()
        │
        ├─ has_credentials()?  NO ──► CredentialsError
        │
        ├─ Prowler available?  yes ──► subprocess + parse ──┐
        ├─ ScoutSuite available? yes ► subprocess + parse ─┤
        │                                                  │
        ├─ both missing ──► boto3 checks ──────────────────┤
        │                                                  │
        ▼                                                  ▼
   raw list of finding dicts  (engine tags on each)
        │
        ▼
analyzer.analyze(raw)
        │  · normalize severity
        │  · dedupe by (control_id, resource) → merge engines
        │  · score 0–100
        │  · counts, redundancy_removed
        ▼
persist Assessment + Finding rows
        │  status = completed | failed (scan_error)
        ▼
Dashboard / Findings / Reports / Comparison read from DB
```

**Redundancy metric:** `raw_count - deduped_count` shown in the assessment detail and in report "Redundancy Note" (proof both engines can run).

---

## 4. Data flow (report generation)

```text
Assessment (id) ──► load findings ──► (optional) AI exec summary
                                      │
                                      ▼
                         render_html / render_json
                                      │
                                      ▼
                    instance/reports/report_*.html|json
                                      │
                                      ▼
                         Report row (type, path)
                                      │
                                      ▼
                         GET /reports/download/<id>  (path checked)
```

---

## 5. Auth flow

```text
First request, no User row  ──► redirect /auth/setup ──► create account
Login page + credentials    ──► session[user_id] set
Any non-auth route, no session ──► redirect /auth/login
Logout ──► session cleared
```

Enforced centrally in one `before_request` so modules cannot forget the wall.

---

## 6. AI flow (optional)

```text
UI button/box ──► POST /ai/* + X-CSRFToken
        │
        ▼
ai_enabled?  no ──► 403
        │ yes
        ▼
rate_limit.check  (10/min · 100/day · 1 concurrent) ──► 429 + Retry-After
        │ ok
        ▼
HTTPS base URL validate ──► OpenAI-compatible chat
        │
        ▼
200 JSON  {success, advice|order|answer}
```

---

## 7. Deployment topology

| Mode | How |
|------|-----|
| Dev | `python run.py` → Flask dev server, `FLASK_DEBUG=1` optional |
| Real audit | `aws configure` + Prowler and/or ScoutSuite installed |

**Not supported in v1:** multi-worker WSGI behind public internet without additional hardening (see `SECURITY.md`).

---

## 8. Technology choices (why)

| Choice | Rationale |
|--------|-----------|
| Flask + blueprints | Small, readable for a 2-person student team; module boundaries match product modules |
| SQLite | Zero ops for localhost; single file easy to back up |
| Subprocess engines | Isolation from the web process; reuse battle-tested scanners |
| Dedupe by control+resource | Cross-engine agreement is the unique value vs. running tools separately |
| Optional WeasyPrint | PDF without making system GTK deps mandatory |
| Feature-flagged AI | Safe default; educators can disable entirely |
