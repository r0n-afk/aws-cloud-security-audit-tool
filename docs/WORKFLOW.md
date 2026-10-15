# User Workflows — AWS Cloud Security Audit Tool

End-to-end journeys an operator follows. Screens map 1:1 to blueprints/templates (see `UI_DESIGN.md`).

---

## 0. First run (one time)

```text
Open http://127.0.0.1:5000
        │
        ▼
No account exists ──► forced to /auth/setup
        │
        ▼
Choose username + password (≥8) ──► account stored (hashed)
        │
        ▼
Redirect /auth/login ──► credentials ──► Dashboard
```

Every later session starts at login. No default credentials ship with the app.

---

## 1. Real AWS scan

**Preconditions:** AWS credentials configured; Prowler and/or ScoutSuite installed (optional but recommended).

| Step | Action | Result |
|------|--------|--------|
| 1 | Start assessment → Run | Credential probe |
| 3a | Creds present + engines installed | Prowler runs → ScoutSuite runs → merged |
| 3b | Creds present, engines missing | boto3 fallback checks run (`engines=boto3`) |
| 3c | **No credentials** | `CredentialsError` — clear message, assessment `failed` |
| 3d | Engine crash/timeout | Recorded in `errors` / `scan_error`; partial results kept if any engine succeeded |
| 4 | Review findings with real ARNs/control IDs | Dedupe provenance e.g. `prowler,scoutsuite` visible |
| 5 | Generate report | Redundancy note shows `raw_count − deduped_count` |
| 6 | Remediate in AWS console | Track status in app |
| 7 | Later: re-scan → compare | Trend: score up, criticals down |

---

## 2. Findings triage loop

```text
Findings list
   │  filter: severity = critical | search title/ARN
   ▼
Open finding detail
   │  read description + recommendation
   │  (optional, AI on) ──► "Get AI advice" ──► advice panel
   ▼
Set remediation_status ──► open / in progress / remediated / accepted
   │
   ▼
Remediation board + next assessment comparison reflect change
```

---

## 3. Report generation

```text
Reports screen ──► choose assessment + format
        │
        ├─ html ──► always works
        ├─ json ──► always works (meta + findings)
        └─ pdf  ──► WeasyPrint? yes → pdf
                        no  → HTML fallback + note
        ▼
List shows generated reports ──► Download (path-safe)
```

Report structure: Executive Summary → Overview → Findings table → Severity breakdown → Redundancy Note → Recommendations.

---

## 4. Optional AI assist

| Step | Action |
|------|--------|
| 1 | Settings → enable AI, set HTTPS base URL + key + model |
| 2 | Save (key masked on re-render) |
| 3 | Finding detail → remediation advice **or** Assessment → prioritize **or** Findings → Q&A box |
| 4 | Rate limit hit → 429 shows retry-after |
| 5 | Disable AI → endpoints return 403 immediately |

Default is **off** — scans and reports work with AI never configured.

---

## 5. Settings maintenance

| Task | Path |
|------|------|
| Theme | Settings → theme |
| AI config | Settings → AI panel (masked) |
| Rotate app secret | Delete `instance/secret_key`, restart |
| Full reset | Stop app → delete `instance/csa_tool.db` → `/auth/setup` again |

---

## 6. Error paths (expected UX)

| Condition | Behavior |
|-----------|----------|
| Not logged in | Redirect login; return to intended page after |
| Wrong password | Inline error + fail delay |
| No AWS creds | Assessment failed; message tells operator to `aws configure` |
| No engines + no boto3 results | `EngineUnavailableError` surfaced on assessment |
| AI off | 403 JSON on AI routes |
| AI over limit | 429 + Retry-After |
| PDF libs missing | HTML fallback with explanatory note |
| Report id tampering | 404 / path guard denies |

---

## 7. Contributor workflow (project process)

```text
User (code)                 Friend (docs)
   │                              │
   ├─ src/, run.py, config,      ├─ README, SECURITY, LICENSE
   │  requirements, .gitignore,  ├─ docs/* (SRS, ARCH, DB, …)
   │  tests/, smoke_test         │
   │                              │
   └────────► GitHub ◄────────────┘
        Insights → Contributors shows both
```

All git commands are run by the project owner (see `04-Git-Handoff` in the vault copy).
