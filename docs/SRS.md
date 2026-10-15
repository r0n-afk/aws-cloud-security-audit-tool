# AWS Cloud Security Audit Tool — Software Requirements Specification (SRS)

**Version:** 1.0  
**Authors:** Ron · Project Partner  
**Status:** Draft (aligned to implemented v1.0)

---

## 1. Introduction

The AWS Cloud Security Audit Tool is a Python/Flask web application that automates AWS cloud security auditing. It collects findings from open-source scanners, analyzes and deduplicates risks, generates professional reports, and compares security posture across multiple scans — all through a single local interface.

### 1.1 Definitions

| Term | Meaning |
|------|---------|
| Assessment (scan) | One execution of the scanner pipeline against an account/region set |
| Finding | A single security issue with severity, category, resource, and recommendation |
| Engine | Prowler, ScoutSuite, or boto3 checks |
| Dedupe | Merge of equivalent findings across engines (same control/resource) |
| Security score | 0–100 derived from severity-weighted open findings |

### 1.2 References

- Product Requirements Document: `Cloud-Security-Audit-Tool.md`
- Architecture: `docs/ARCHITECTURE.md`
- Security model: `SECURITY.md`

---

## 2. Problem statement

Cloud environments accumulate misconfigurations (over-permissive IAM, public buckets, missing encryption/logging). Security teams run multiple scanners, then manually reconcile overlapping output formats into something presentable. Results scatter across tools, making posture tracking and report generation painful — especially for students, auditors, and small teams without a SIEM.

## 3. Objectives

- Audit AWS resources through a unified web workflow.
- Run **two** independent scanners when available and surface redundancy (what both agree on).
- Deduplicate findings while keeping engine provenance.
- Generate professional HTML / PDF / JSON reports.
- Compare previous vs. current assessments (score + severity trends).
- Operate fully offline (localhost) with optional AI assist.

---

## 4. Overall description

### 4.1 User classes

| Persona | Primary need |
|---------|--------------|
| Security analyst | Review findings, prioritize, report |
| Security engineer | Posture visibility, remediation tracking |
| Auditor / student | Evidence trail, learning workflow |

### 4.2 Operating environment

- Python 3.10–3.14 · Flask 3 · SQLite (Flask-SQLAlchemy)
- Windows / Linux / macOS · localhost binding (`127.0.0.1:5000`)
- Optional binaries: Prowler, ScoutSuite, WeasyPrint system libs, OpenAI-compatible endpoint

### 4.3 Constraints

- Single local account; no multi-tenancy in v1
- Scans require real AWS credentials; missing credentials must error clearly (no simulated fallback)
- AI is **opt-in**, rate-limited, HTTPS-only endpoints (loopback exception for Ollama)
- Read-only AWS credentials recommended

### 4.4 Assumptions

- Operator can install optional scanners themselves
- First run is offline (no cloud dependency for setup/login)

---

## 5. Specific requirements

### 5.1 Functional requirements

| ID | Requirement | Notes |
|----|-------------|-------|
| FR-01 | First-run account setup | `/auth/setup` — username + password (min 8), hashed |
| FR-02 | Session login | Required for all app routes; logout ends session |
| FR-03 | Start assessment | Name + optional description |
| FR-04 | Dual-engine scan | Prowler + ScoutSuite both attempted when available |
| FR-05 | boto3 fallback | Used only if neither external engine runs |
| FR-07 | Hard fail without creds | No creds → clear error, no simulated fallback |
| FR-08 | Normalize findings | Map engine output → common schema (severity, category, title, description, recommendation, resource, control_id, engines) |
| FR-09 | Deduplicate | Same control+resource across engines → one finding; provenance retained; raw vs deduped counts stored |
| FR-10 | Severity classification | critical / high / medium / low / informational |
| FR-11 | Security score | Severity-weighted 0–100; stored on assessment |
| FR-12 | Findings workspace | List, search, filter, sort; detail page |
| FR-13 | Remediation tracking | Per-finding status (open / in progress / remediated / accepted) |
| FR-14 | Reports | HTML, JSON always; PDF when WeasyPrint present (else HTML fallback) |
| FR-15 | Report sections | Exec Summary → Overview → Findings → Severity → Redundancy note → Recommendations |
| FR-16 | Report download | Confined to reports folder; path-traversal blocked |
| FR-17 | History | List past assessments; detail view |
| FR-18 | Comparison | Two assessments side-by-side: score, counts, severity deltas |
| FR-19 | Dashboard | Latest score, totals, severity breakdown, quick actions |
| FR-20 | Settings | Theme, report format, AI on/off + endpoint/key/model, rate limits; secrets masked on render |
| FR-21 | AI remediation advice | POST `/ai/remediation/<id>` when AI enabled |
| FR-22 | AI prioritization | POST `/ai/prioritize/<id>` — AI order + severity order |
| FR-23 | AI Q&A | POST `/ai/qna` — answer from stored findings context (≤500 chars question) |
| FR-24 | AI rate limits | 10/min, 100/day, 1 concurrent → 429 with Retry-After |
| FR-25 | Audit log | Auth events recorded |

### 5.2 Non-functional requirements

| Category | Requirement |
|----------|-------------|
| Performance | Scan bounded by 30 min timeout; web UI responsive for ≤10k findings |
| Reliability | Engine partial failure recorded, not process-fatal; all engines fail → assessment marked failed with `scan_error` |
| Usability | ≤3 clicks from dashboard to start scan; severity legible without color-only reliance |
| Security | See `SECURITY.md` (CSRF, headers, sandbox, no secrets in repo) |
| Portability | Pure Python + pip deps; engines optional |
| Maintainability | Blueprint modular layout; tests for analyzer/scanner/auth/routes |
| Availability | Localhost single-process; no HA requirement |

---

## 6. External interface requirements

| Interface | Detail |
|-----------|--------|
| UI | Browser (modern evergreen); base layout + module templates |
| AWS API | Via Prowler / ScoutSuite / boto3 using ambient credentials |
| AI API | OpenAI-compatible `POST /chat/completions` (or equivalent) over HTTPS |
| Files | SQLite DB under `instance/`; reports under `instance/reports/` |

---

## 7. Verification & validation

| Method | Coverage |
|--------|----------|
| Unit tests | Analyzer (dedupe, score, prioritize), scanner parsing (fixtures), rate limiter |
| Integration tests | Auth cycle, full route smoke, report generation, settings save, AI 403 path |
| E2E script | `smoke_test.py` — setup → login → canned scan (mocked engine) → reports → all modules |
| Manual gate | P5 user go/no-go on running app |

---

## 8. Out of scope (v1)

Real-time monitoring · RBAC / multi-user · multi-cloud · automated remediation · compliance mapping UI · public internet deployment.

## 9. Future enhancements (v2 sketch)

Deeper AI analysis · compliance benchmarks (CIS) · team workspaces · risk scoring engine · multi-environment profiles.
