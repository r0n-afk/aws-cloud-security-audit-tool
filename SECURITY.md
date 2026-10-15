# Security Policy & Model — AWS Cloud Security Audit Tool

**Version:** 1.0 · **Scope:** v1.0 single-operator, localhost deployment

---

## Threat model (what we defend against)

| Asset | Threat | Control |
|-------|--------|---------|
| AWS account | Credential leak into git/DB/logs | Creds only via `~/.aws` or env; never stored; `.gitignore` blocks `instance/`, `.env`, keys |
| App session | CSRF on state-changing routes | Flask-WTF CSRF on all POSTs + `X-CSRFToken` for AJAX |
| App session | Session fixation / theft | HttpOnly, SameSite=Lax cookies; SECRET_KEY generated once into `instance/secret_key` (not in git) |
| Account | Brute-force login | Delay on failed attempts; single local account; no default creds |
| Scanner | Command injection | `subprocess` with argument lists only (no `shell=True`); fixed argv; timeouts; output size caps |
| Reports | Path traversal on download | Report IDs resolved through ORM; path confined to `REPORTS_FOLDER` |
| Browser | Clickjacking / MIME sniffing | `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, CSP headers |
| AI endpoint | Abuse / cost runaway | OFF default; HTTPS-only base URL (localhost Ollama allowed); 10/min · 100/day · 1 concurrent; audit-logged |
| Supply chain | Known CVE in deps | Pinned `requirements.txt`; `pip-audit` in CI/P4; secret grep pre-push |

## Authentication & session

- First run → `/auth/setup` → create username + password (Werkzeug `generate_password_hash`).
- Login required for every non-auth/static route (`before_request` guard in `src/app/__init__.py`).
- Single local account. No multi-tenancy, no password reset flow (delete `instance/csa_tool.db` and re-setup if needed).
- Failed logins incur a configurable delay (`LOGIN_FAIL_DELAY`, default 0 in tests, >0 in production config).
- Audit rows written on login success/failure (`audit` module).

## Credentials (AWS)

- Use a **read-only** IAM principal (AWS managed policy `SecurityAudit`).
- Preferred sources, in order: environment variables → shared credentials file (`~/.aws/credentials`) → instance profile (if any).
- Never commit `.aws/`, `credentials`, `*.pem`, `*.key`, `.env` (already in `.gitignore`).
- `CredentialsError` is raised when no credentials are found — the app **hard-fails** rather than substituting simulated results.

## Scanner sandbox

- Prowler / ScoutSuite invoked as fixed argv with `timeout=1800` (configurable).
- Parse only known JSON shapes; unknown fields ignored.
- No runtime `pip install` of engines from the app — operators install tools themselves.
- Engine failures are collected into `assessment.scan_error` / `errors[]`, never fatal to the web process unless *all* engines fail.

## AI module

- Disabled by default (`ai_enabled=false`).
- Base URL must be `https://` except loopback (`localhost` / `127.0.0.1`) for local Ollama.
- Prompts include only finding text already stored locally — no raw AWS credentials are ever sent.
- Rate limiter is server-side and resets per minute/day window; responses return `429` with `Retry-After`.

## Application hardening (Tier 1 + 2 checklist)

- [x] CSRF protection on all forms and JSON POSTs
- [x] Security response headers (frame, nosniff, referrer, CSP)
- [x] ORM-only SQL (Flask-SQLAlchemy) — no string-built queries
- [x] Path-traversal guard on report download
- [x] `.gitignore` hardened (`instance/`, reports, keys, caches)
- [x] Instance-persisted `SECRET_KEY` (not committed)
- [x] Rate limit on assessment creation
- [x] Structured audit log for auth events
- [x] No stack traces to clients in production mode
- [ ] `pip-audit` run (P4 — see below)
- [ ] Pre-push secret grep (AKIA / sk- / literals)

### Dependency audit

```bat
pip install pip-audit
python -m pip_audit -r requirements.txt
```

### Secret grep (pre-push)

```bat
git grep -nE "(AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|password\s*=\s*['\"][^'\"]{8,})"
```

Zero matches required before any push.

## What this is NOT

- Not a multi-user SaaS. Not hardened for public internet exposure.
- No automated remediation (read-only recommendations only).
- No real-time monitoring or agent-based collection in v1.

**If you expose it anyway:** put it behind HTTPS (reverse proxy), restrict to VPN/LAN, enable fail2ban-style rate limiting, and rotate the SECRET_KEY.

## Reporting a vulnerability

Open a **private** security advisory on the GitHub repo (or contact the maintainers directly). Do not file public issues containing exploit details or real AWS credentials.

## Roadmap (Tier 3 — out of scope for v1)

- Optional SQLCipher DB encryption
- Report retention / purge UI
- Advanced rate-limit dashboards
- Multi-user RBAC
