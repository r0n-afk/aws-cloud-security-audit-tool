# Release Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a publishable GitHub repo (beginners → experts): CI, honest version claims, first-class demo mode, dev-install path, screenshots, contributor docs, per-scan AWS identity (option A), release prep.

**Architecture:** Docs/tests/CI work plus one feature addition: `Assessment.aws_account_id` + `Assessment.aws_arn` populated from `sts:GetCallerIdentity` at scan time. Native execution; local commit per task; **no push until owner approves**.

**Tech Stack:** pytest 9.1.1, GitHub Actions, Flask 3.1.3, boto3 STS, Markdown docs.

**Spec:** This plan + conversation decisions recorded in `D:\Generator\OpenCode-Library\decisions.md` (github-user, push-gate, python-support, demo-mode, scan-identity, execution rows).

## Global Constraints

- Repo root: `D:\Generator\OpenCode-Library\AWS-cloud-security-Audit-tool\Projects\aws-cloud-security-audit-tool`.
- **NO `git push` until the owner explicitly approves at the end** (push-gate lock). Commits allowed (delegated).
- GitHub account **`r0n-afk`** — never `r0n-k` — in remote URL, badges, docs.
- Python **3.10–3.14** (en-dash `–` exactly) in all claims.
- Local test command: `.venv\Scripts\python.exe -m pytest tests -q`. CI: `python -m pytest tests -q`.
- Never run `smoke_test.py` alongside pytest (wipes `instance/csa_tool.db`).
- No new runtime dependencies; dev/CI deps only (`requirements-dev.txt`, workflow pip installs).
- Invariants: default mode `aws`; missing creds hard-fail (SRS FR-06/07); demo manual-only; engine names visible in docs; README says "tool"; keys stay in `~/.aws`.

## Review Focus

1. Fresh clone lacks pytest → Task 1 `test_requirements_dev_pins_pytest`.
2. Python 3.15 user hits wheel build failure silently → Task 2 `test_readme_states_python_version_floor`.
3. Scanner mode flipped but Save button never appears → Task 3 `test_settings_scanner_mode_in_app_save_dirty_list`.
4. CI red on ubuntu (hoisted weasyprint import → GTK crash) → Task 4 `test_weasyprint_import_stays_lazy`.
5. Wrong account in links/remote → Task 0 remote check + Task 4 `test_readme_links_match_repo_identity`.
6. Existing SQLite DBs lack new identity columns → Task 7 `ensure_identity_columns` idempotent migration test.

---

### Task 0: Preflight — locks, plan save, remote, identity, baseline commit

**Files:**
- Create: `docs/superpowers/plans/2026-10-10-release-readiness.md` (this file)
- Modify: git config (local), git remote (owner-delegated)

**Interfaces:**
- Produces: clean tree, `origin` = `https://github.com/r0n-afk/aws-cloud-security-audit-tool.git`, identity `Rohan Kolte <181756752+r0n-afk@users.noreply.github.com>`.

- [x] Step 1: Locks written to `D:\Generator\OpenCode-Library\decisions.md`.
- [x] Step 2: Save this plan verbatim.
- [ ] Step 3: `git remote set-url origin https://github.com/r0n-afk/aws-cloud-security-audit-tool.git`
- [ ] Step 4: `git config user.name "Rohan Kolte"`; `git config user.email "181756752+r0n-afk@users.noreply.github.com"`
- [ ] Step 5: Verify `git remote get-url origin` contains `r0n-afk`.
- [ ] Step 6: `git add -A` + `git commit -m "feat: settings save button, mode-gated results, README/docs refresh"` (NO push).
- [ ] Step 7: `git status --short` empty.

### Task 1: Dev install path

**Files:** Create `requirements-dev.txt` (`pytest==9.1.1`), `tests/test_docs.py`; Modify README `## Tests`.

- [ ] Step 1 failing tests: `test_requirements_dev_pins_pytest` (assert `'pytest==' in _read('requirements-dev.txt')`), `test_readme_tests_section_installs_dev_requirements` (assert `'requirements-dev.txt' in _read('README.md')`); `_read(*parts)` helper opens UTF-8 relative to `BASE = tests/..`.
- [ ] Step 2 run → FAIL (FileNotFoundError).
- [ ] Step 3 create file + README Tests blocks add `pip install -r requirements-dev.txt` line above pytest in both Windows and Linux blocks.
- [ ] Step 4 run → 40 passed.
- [ ] Step 5 commit `feat: dev requirements + README test install path` (NO push).

### Task 2: Python floor 3.10–3.14

**Files:** README line 5 + note under first-open line; `docs/SRS.md` line 58; `tests/test_docs.py`.

- [ ] Step 1 failing tests: `test_readme_states_python_version_floor` (`'3.10–3.14' in txt` and `'Python 3.10+' not in txt`), `test_srs_states_python_version_floor` (same against `docs/SRS.md`).
- [ ] Step 2 run → FAIL.
- [ ] Step 3 edits: README status line `**Python 3.10–3.14**`; after first-open line add blockquote: `> **Python note:** 3.10–3.14 supported. Python 3.15 is not yet supported — some pinned dependencies ship no prebuilt wheels, so pip install fails without a C compiler.`; SRS `| Python 3.10–3.14 · Flask 3 · SQLite (Flask-SQLAlchemy) |`.
- [ ] Step 4 run → 42 passed.
- [ ] Step 5 commit `docs: pin supported Python range 3.10-3.14` (NO push).

### Task 3: Scanner mode first-class

**Files:** `src/app/templates/settings/index.html` (line 79 unhide, label, help text, JS 179-200 removal, appFieldNames add); `tests/test_app.py` replace lines 90-97; README Scanner modes + Application Settings; `docs/UI_DESIGN.md` line 76.

- [ ] Step 1 failing tests replacing `test_settings_dev_scanner_panel_hidden_by_default`:
```python
def test_settings_scanner_mode_visible_by_default(auth_client):
    page = auth_client.get('/settings/')
    html = page.get_data(as_text=True)
    assert 'id="devScannerMode"' in html
    assert 'data-dev-panel' not in html
    assert '>Scanner mode<' in html
    assert 'Demo mode runs without AWS credentials' in html


def test_settings_scanner_mode_in_app_save_dirty_list(auth_client):
    page = auth_client.get('/settings/')
    html = page.get_data(as_text=True)
    assert "'setting_scanner_mode'" in html
```
- [ ] Step 2 run → new tests FAIL; toggle test still PASSES.
- [ ] Step 3 edits: remove `hidden data-dev-panel`; label `Mode`→`Scanner mode`; help text `Demo mode runs without AWS credentials — sample findings for walkthroughs. Mode switching is manual; AWS mode without credentials still fails hard.`; delete JS title/panel/modeSelect block (keep IIFE + aiToggle + rest); add `'setting_scanner_mode',` first in appFieldNames; README Scanner modes append `Switch modes under **Settings → Application Settings → Scanner mode** (Demo runs without AWS credentials). Mode changes apply to the next assessment; existing results stay scoped to their mode.`; README Application Settings `...one of them or Scanner mode changes.`; UI_DESIGN line 76 append ` Mode control lives in Settings → Application Settings → Scanner mode.`
- [ ] Step 4 run → 44 passed.
- [ ] Step 5 commit `feat: first-class scanner mode control with save-button wiring` (NO push).

### Task 4: CI workflow + badges

**Files:** `.github/workflows/tests.yml`; README badges; `tests/test_docs.py`.

- [ ] Step 1 failing tests:
```python
def test_ci_workflow_runs_pytest_on_supported_pythons():
    txt = _read('.github', 'workflows', 'tests.yml')
    assert 'pytest tests' in txt
    assert "'3.10'" in txt and "'3.14'" in txt
    assert 'windows-latest' in txt and 'ubuntu-latest' in txt
    assert 'timeout-minutes: 15' in txt
    assert 'pip-audit' in txt


def test_weasyprint_import_stays_lazy():
    with open(os.path.join(BASE, 'src', 'reports', 'render.py'), encoding='utf-8') as f:
        for line in f:
            s = line.strip()
            if s.startswith('from weasyprint') or s.startswith('import weasyprint'):
                assert line.startswith(' '), f'weasyprint import must stay inside a function: {s}'


def test_readme_links_match_repo_identity():
    txt = _read('README.md')
    assert 'github.com/r0n-afk/aws-cloud-security-audit-tool' in txt
    assert 'github.com/r0n-k/' not in txt
```
- [ ] Step 2 run → FAIL (missing file).
- [ ] Step 3 workflow:
```yaml
name: tests

on:
  push:
  pull_request:

jobs:
  pytest:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, windows-latest]
        python-version: ['3.10', '3.14']
    runs-on: ${{ matrix.os }}
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install dependencies
        run: pip install -r requirements.txt -r requirements-dev.txt
      - name: Run tests
        run: python -m pytest tests -q

  audit:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    continue-on-error: true
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.14'
      - name: Install pip-audit
        run: pip install pip-audit
      - name: Audit runtime dependencies (advisory)
        run: pip-audit -r requirements.txt
```
README badges after title: tests badge (actions/workflows/tests.yml), python `3.10–3.14` shield (URL-encoded en dash), license Apache 2.0 shield — all under `r0n-afk/aws-cloud-security-audit-tool`.
- [ ] Step 4 local CI sim: `pip install -r requirements.txt -r requirements-dev.txt` + full suite → 47 passed.
- [ ] Step 5 commit `ci: pytest matrix with timeout, advisory pip-audit, README badges` (NO push).

### Task 5: Screenshots + 5-minute demo path

**Files:** `docs/images/{dashboard,findings,settings}.png` (captured from running app); README `## Screenshots` + `### First scan in 5 minutes (no AWS)`; `tests/test_docs.py`.

- [ ] Step 1 start app, setup/login, demo mode, one assessment; capture 3 screenshots 1280px → docs/images/.
- [ ] Step 2 verify Test-Path ×3 → all True (else stop).
- [ ] Step 3 failing test:
```python
def test_readme_image_links_resolve():
    import re
    txt = _read('README.md')
    for rel in re.findall(r'!\[[^\]]*\]\(([^)]+)\)', txt):
        assert os.path.exists(os.path.join(BASE, rel)), f'broken image: {rel}'
```
- [ ] Step 4 embed Screenshots section (before Quick start) + First scan in 5 minutes (after Scanner modes, 5 numbered steps: setup account → Settings Scanner mode Demo → New assessment → explore modules → switch back to AWS).
- [ ] Step 5 run → 48 passed.
- [ ] Step 6 commit `docs: screenshots + 5-minute demo quick path` (NO push).

### Task 6: CONTRIBUTING.md

- [ ] Step 1 failing test: `test_contributing_documents_maintainer_split` (`r0n-afk`, `genrex-bot`, `requirements-dev.txt`, `pytest tests` all in file).
- [ ] Step 2 run → FAIL.
- [ ] Step 3 create CONTRIBUTING.md (maintainer table: code→@r0n-afk, docs→genrex-bot; dev setup referencing README + dev requirements; commit prefixes feat/fix/docs/test/ci; guidelines: keys stay ~/.aws, demo manual, python 3.10–3.14; security→SECURITY.md) + README Documentation table row.
- [ ] Step 4 run → 49 passed.
- [ ] Step 5 commit `docs: contributing guide with maintainer split` (NO push).

### Task 7: Assessment identity columns (option A) — model + migration

**Files:** `src/app/models/assessment.py`; `src/app/__init__.py` (or a small helper); `tests/test_app.py`.

**Interfaces:**
- Produces: `Assessment.aws_account_id` (String(20), default `''`), `Assessment.aws_arn` (String(200), default `''`); `ensure_identity_columns(engine)` — idempotent ALTER TABLE helper called in `create_app` after `db.create_all()`.

- [ ] Step 1 failing tests:
```python
def test_assessment_has_identity_columns():
    from app.models.assessment import Assessment
    assert hasattr(Assessment, 'aws_account_id')
    assert hasattr(Assessment, 'aws_arn')


def test_ensure_identity_columns_idempotent(app):
    from app import ensure_identity_columns
    from app.extensions import db
    ensure_identity_columns(db.engine)
    ensure_identity_columns(db.engine)
    with app.app_context():
        from sqlalchemy import text
        rows = db.session.execute(text('PRAGMA table_info(assessments)')).fetchall()
        names = [r[1] for r in rows]
        assert 'aws_account_id' in names and 'aws_arn' in names
```
- [ ] Step 2 run → FAIL (AttributeError).
- [ ] Step 3 add columns to model; add `ensure_identity_columns(engine)` in `src/app/__init__.py`:

```python
def ensure_identity_columns(engine):
    from sqlalchemy import inspect, text
    cols = {c['name'] for c in inspect(engine).get_columns('assessments')}
    with engine.begin() as conn:
        if 'aws_account_id' not in cols:
            conn.execute(text('ALTER TABLE assessments ADD COLUMN aws_account_id VARCHAR(20)'))
        if 'aws_arn' not in cols:
            conn.execute(text('ALTER TABLE assessments ADD COLUMN aws_arn VARCHAR(200)'))
```
call it inside `create_app` right after existing `db.create_all()` block (find exact call site; wrap in try/except TableNotFound → no-op only if table truly absent — create_all precedes so table exists).

- [ ] Step 4 run → 51 passed.
- [ ] Step 5 commit `feat: assessment identity columns (aws_account_id, aws_arn)` (NO push).

### Task 8: STS wiring + display

**Files:** `src/scanner/aws_checks.py` (reuse/extend `test_connection`), `src/scanner/orchestrator.py`, `src/app/modules/assessment/services.py`, history templates, `tests/test_app.py` + `tests/test_scanner.py`.

**Interfaces:**
- Produces: `run_scan(...)` result gains `aws_account_id: str`, `aws_arn: str` (`''` when unknown, `'demo'` in demo mode); assessment service persists both; History list + detail display `account_id` (ARN in detail).

- [ ] Step 1 failing tests:
```python
def test_demo_scan_stores_demo_identity(auth_client, app):
    aid = _demo_scan(auth_client, app, 'Identity Demo')
    with app.app_context():
        from app.models.assessment import Assessment
        a = Assessment.query.get(aid)
        assert a.aws_account_id == 'demo'
        assert a.aws_arn == ''


def test_history_detail_shows_account(auth_client, app):
    aid = _demo_scan(auth_client, app, 'Identity Show')
    r = auth_client.get(f'/history/{aid}')
    assert b'account' in r.data.lower()
```
- [ ] Step 2 run → FAIL.
- [ ] Step 3 implement: orchestrator demo branch sets `'aws_account_id': 'demo', 'aws_arn': ''`; aws branch calls a new best-effort `identity()` helper in aws_checks (STS GetCallerIdentity via default session; returns `(account, arn)` or `('', '')` on any exception — identity probe must NEVER fail the scan); `run_assessment` service writes both fields to the model; templates: history list shows `<span class="badge">account</span>` if present, detail shows ARN.
- [ ] Step 4 run → 53 passed + full suite green.
- [ ] Step 5 commit `feat: per-scan AWS identity (STS account + ARN) recorded on assessments` (NO push).

### Task 9: v0.1.0 release prep + final verification

**Files:** Create `docs/releases/v0.1.0-notes.md`.

- [ ] Step 1 full suite: expect 53 passed, 0 failed.
- [ ] Step 2 write release notes: title, date, highlights (Prowler+ScoutSuite dedupe, mode-gated results, demo mode, CI, identity capture, AI optional), install pointer to README, known limits (Python ≤3.14, localhost only, PDF needs GTK on some systems).
- [ ] Step 3 verify: `git remote get-url origin` → r0n-afk; `git status --short` → empty; grep repo for `r0n-k` → zero file matches; list commits `git log --oneline`.
- [ ] Step 4 Report completion to owner: task summary, test count, commit list, screenshots/caveats → **await explicit push approval** (push-gate). On approval: `git push -u origin <branch>`, verify Actions run, create `v0.1.0` tag + release.
