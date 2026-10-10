# Contributing

Two-maintainer student showcase project. PRs and issues welcome from beginners and experts alike.

## Maintainers & ownership

| Area | Maintainer |
|------|-----------|
| Code (`src/`, `tests/`, `run.py`, `config.py`, `requirements*.txt`) | [Rohan Kolte (@r0n-afk)](https://github.com/r0n-afk) |
| Docs (`README.md`, `docs/`, `SECURITY.md`, `CONTRIBUTING.md`) | [genrex-bot](https://github.com/genrex-bot) |

## Dev setup

Follow **README → Quick start** (Windows or Linux block), then:

```bash
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest tests -q
```

All tests must pass locally before pushing; CI runs the same command on ubuntu + windows for Python 3.10 and 3.14.

## Commit style

Prefix + imperative summary: `feat:`, `fix:`, `docs:`, `test:`, `ci:`.

## Guidelines

- Keep the AWS credential rule: keys stay in `~/.aws`, never stored in the app or its database.
- Demo mode is manual only; missing AWS credentials must fail hard (never silently fall back).
- Supported Python: 3.10–3.14.

## Security issues

Report privately per [SECURITY.md](SECURITY.md) — do not open public issues for vulnerabilities.
