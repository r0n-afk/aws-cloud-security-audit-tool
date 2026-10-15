# Database Design — AWS Cloud Security Audit Tool

**Engine:** SQLite via Flask-SQLAlchemy  
**File:** `instance/csa_tool.db` (gitignored)  
**Schema create:** `db.create_all()` inside app factory on startup  
**Models package:** `src/app/models/`

---

## 1. Entity-relationship overview

```text
User 1 ──── (session only; no FK)

Assessment 1 ──── * Finding
Assessment 1 ──── * Report

Setting  * ──── singleton rows (key/value)
AuditLog *      append-only events
```

No multi-user FK graph: one `User` row is the local account. Assessments are not user-scoped in v1 (single operator).

---

## 2. Tables

### 2.1 `users`

| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
| id | INTEGER | PK | |
| username | VARCHAR(80) | NOT NULL, UNIQUE | login name |
| password_hash | VARCHAR(256) | NOT NULL | Werkzeug hash — never plaintext |
| created_at | DATETIME | NOT NULL, default utcnow | |
| last_login | DATETIME | nullable | updated on success |

### 2.2 `assessments`

| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
| id | INTEGER | PK | |
| name | VARCHAR(200) | NOT NULL | user label |
| description | TEXT | nullable | |
| assessment_date | DATETIME | NOT NULL | when scan started |
| completion_date | DATETIME | nullable | set when completed |
| security_score | FLOAT | default 0.0 | 0–100 from analyzer |
| total_findings | INTEGER | default 0 | deduped count |
| critical_count … informational_count | INTEGER | default 0 | five severity buckets |
| status | VARCHAR(20) | NOT NULL, default `pending` | pending → running → completed \| failed |
| engines_used | VARCHAR(200) | default `''` | e.g. `prowler,scoutsuite` or `boto3` |
| raw_count | INTEGER | default 0 | pre-dedupe |
| deduped_count | INTEGER | default 0 | post-dedupe |
| scan_error | TEXT | nullable | failure details / engine errors |
| created_at / updated_at | DATETIME | NOT NULL | audit timestamps |

**Relationships:** `findings` (1→*, cascade delete-orphan), `reports` (1→*, cascade delete-orphan).

### 2.3 `findings`

| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
| id | INTEGER | PK | |
| assessment_id | INTEGER | FK → assessments.id, NOT NULL | owner |
| severity | VARCHAR(20) | NOT NULL | critical \| high \| medium \| low \| informational |
| category | VARCHAR(100) | NOT NULL | e.g. IAM, Network Security |
| title | VARCHAR(300) | NOT NULL | |
| description | TEXT | NOT NULL | |
| recommendation | TEXT | nullable | remediation text |
| status | VARCHAR(20) | NOT NULL, default `open` | generic finding state |
| remediation_status | VARCHAR(20) | NOT NULL, default `open` | open \| in progress \| remediated \| accepted |
| resource | VARCHAR(500) | default `''` | ARN / resource id |
| control_id | VARCHAR(200) | default `''` | scanner control key (dedupe part 1) |
| engines | VARCHAR(200) | default `''` | provenance e.g. `prowler,scoutsuite` |
| created_at / updated_at | DATETIME | NOT NULL | |

**Indexes:**

| Index | Columns | Purpose |
|-------|---------|---------|
| idx_findings_assessment | assessment_id | detail/history loads |
| idx_findings_severity | severity | filter/sort |
| idx_findings_status | status | list filters |
| idx_findings_remediation | remediation_status | remediation board |

**Dedupe key (logical, not DB unique):** `(control_id, resource)` within one assessment — enforced in `src/analyzer`, not as a SQL constraint (engines may emit slight control-id variants).

### 2.4 `reports`

| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
| id | INTEGER | PK | |
| assessment_id | INTEGER | FK → assessments.id, NOT NULL | |
| report_type | VARCHAR(10) | NOT NULL | `html` \| `pdf` \| `json` |
| report_path | VARCHAR(500) | NOT NULL | absolute path under `REPORTS_FOLDER` |
| generated_date | DATETIME | NOT NULL | |
| created_at | DATETIME | NOT NULL | |

**Index:** `idx_reports_assessment (assessment_id)`.

### 2.5 `settings`

| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
| id | INTEGER | PK | |
| key | VARCHAR(100) | NOT NULL, UNIQUE | |
| value | TEXT | NOT NULL | stored as string |
| description | TEXT | nullable | admin hint |
| created_at / updated_at | DATETIME | NOT NULL | |

**Index:** `idx_settings_key (key)`.

**Default keys** (seeded by `init_default_settings()`):

| Key | Default | Meaning |
|-----|---------|---------|
| theme | `light` | UI theme |
| ai_enabled | `false` | master AI switch |
| ai_base_url | `''` | HTTPS endpoint (loopback http allowed) |
| ai_api_key | `''` | masked in UI |
| ai_model | `''` | model id |
| ai_rate_minute | `10` | per-minute cap |
| ai_rate_day | `100` | per-day cap |

Sensitive keys are never echoed in full to templates (masked by settings service).

### 2.6 `audit_logs`

| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
| id | INTEGER | PK | |
| event | VARCHAR(100) | NOT NULL | e.g. `login_success`, `login_fail` |
| detail | TEXT | nullable | truncated to 1000 chars |
| created_at | DATETIME | NOT NULL | |

Append-only; no updates/deletes from application code.

---

## 3. Score derivation (stored on assessment)

```text
score = max(0, 100 − Σ severity_weight(open findings))
weights: critical=40  high=15  medium=7  low=3  informational=1
empty assessment → 100
```

Computed once at scan completion in `src/analyzer.calculate_score`.

---

## 4. Runtime files (not in DB)

| Path | Content |
|------|---------|
| `instance/secret_key` | Generated SECRET_KEY (0600 intent; gitignored) |
| `instance/reports/*` | Generated HTML/PDF/JSON blobs |
| `instance/csa_tool.db` | SQLite database file |

All under `instance/` → excluded by `.gitignore`.

---

## 5. Migration policy (v1)

- No Alembic in v1 — schema evolves with `create_all` for fresh installs.
- Dev reset: stop app → delete `instance/csa_tool.db` → restart → re-run `/auth/setup`.
- If columns are added later: ship a tiny `upgrade()` helper or instruct users to recreate (student project acceptable).

---

## 6. Query patterns (hot paths)

| UI need | Query shape |
|---------|-------------|
| Dashboard latest | `Assessment.query.order_by(id.desc()).first()` + counts |
| Findings table | `Finding.query.filter_by(assessment_id=…)` + filter severity/status |
| History | `Assessment.query.order_by(assessment_date.desc())` |
| Comparison | load two assessments + grouped finding counts |
| Remediation board | `filter(remediation_status != 'remediated')` |
| Report download | `Report.query.get(id)` → validate `report_path` prefix |
