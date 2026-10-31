---
name: pre-ship-audit
description: Systematic debug, security, privacy, and production audit to run before pushing, tagging, releasing, publishing a package/container, or deploying ColdTrail. Use whenever the user asks to ship, release, publish, deploy, tag, open a release PR, or verify production readiness.
---

# Pre-ship audit

Run this before any remote-visible action. The goal is evidence, not reassurance: find and fix
real defects, then prove the fixed state.

## 0. Freeze and scope

- `git status --short`, `git branch --show-current`, `git log --oneline -5`, `git remote -v`.
- Read `AGENTS.md`, `CONTRIBUTING.md`, `SECURITY.md`, and `AUDIT.md`.
- Confirm what is being shipped and whether push/tag/release/publish was explicitly approved.
- Do not ship with a dirty tree, unresolved conflicts, or uncommitted generated artifacts.

## 1. Static and build checks

```bash
uv sync
uv run ruff check .
uv run ruff format --check .
uv run pytest -q
uv build --wheel
```

- Confirm the wheel contains `coldtrail/data/sites.toml`, `web/templates/`, `web/static/`,
  and `schemas.py`. Build to a fresh directory (`--out-dir /tmp/wheel-check`) so a stale
  `dist/` wheel cannot mask a missing module.
- Run `uvx bandit -r src/coldtrail` and triage every Medium/High finding.
- Run `uvx pip-audit` and investigate known CVEs.
- Secret scan: `gho_`, `ghp_`, `sk-`, `AKIA`, private-key headers, `.env`, DBs, exports.
- Scan for stale product names, dead URLs, TODO/FIXME, `assert` in production paths, and
  `except Exception: pass`.

## 2. Functional smoke tests

- `uv run coldtrail --version` and `--help`.
- `uv run coldtrail doctor --offline --json`; check DB mode, raw/avatar defaults, retention,
  and that proxy credentials are redacted.
- `uv run coldtrail config --json`; check provenance values and that every secret is
  `set`/`unset`, never the value.
- `uv run coldtrail schema --list`; validate one real payload against its schema.
- Offline contract replay for available fixtures: `uv run coldtrail source verify -s <source>`.
  A bare `source verify` fails for sources that intentionally have no fixture.
- Live pivot on a known handle with `--no-save --json` (curated only). Confirm statuses are
  plausible and failures are isolated.
- Exercise the web app with `TestClient` or a local server: `/`, `/runs/{id}`, `/pivot`,
  `/tools`, `/cases`, `/search`, `/api/health`, `/api/runs`, `/api/diff`, SSE job stream.
- TUI: run the Textual pilot tests, not just the CLI.
- Export every format once (json, jsonl, csv, graphml, gexf, dot, html, md, stix, sarif,
  maltego); verify `--redact`, `--encrypt`, `decrypt`, `diff --format html`, and case dossiers.
- Evidence: add, list, export, verify; corrupt a blob and confirm detection.
- Retention: create an old run/evidence/audit row, run `prune`, confirm rows and blobs vanish.

## 3. Security audit

- Auth: bearer, `X-API-Key`, cookie; wrong token rejected; `/login` rate-limited; `/logout`
  clears; cookies are HMAC-derived; non-loopback bind refuses without a token.
- Headers: CSP, HSTS on HTTPS, `no-referrer`, `Permissions-Policy`, `Cache-Control: no-store`.
- Uploads: oversized file rejected while streaming; temp files cleaned.
- External tools: option-injection target rejected; unknown/import-only tools rejected;
  no shell; timeout honored.
- SQL: dynamic clauses only from fixed fragments; all values parameterized.
- HTML/URLs: `javascript:`/`data:`/`vbscript:` blocked; autoescape on; filenames sanitized.
- XML: third-party XML parsed with `defusedxml`.
- SSRF/external tools: confirm the web UI is operator-only and documented as such.
- Dependencies: no known CVEs; pinned container/tool versions.

## 4. Privacy audit

- `keep_raw=False` and `avatar_hash=False` by default; config/env override works.
- DB/WAL/SHM, evidence, and CLI exports are `0600`; evidence dirs `0700`; the DB is created
  under `umask(0o077)` (owner-only from creation).
- Tor uses `socks5h`; no local DNS resolution.
- Redirects cannot reach loopback/link-local unless private targets are explicitly allowed.
- `/healthz` returns a fixed detail, not exception text.
- Email targets hashed in cache/raw keys; `final_url` does not leak them.
- API keys absent from cache/raw keys; headers used where supported.
- No telemetry or hidden network calls; `doctor --offline` makes none.
- Pwned Passwords sends only the 5-char prefix and never returns/logs the prefix/password/hash.
- Audit log redacts tokens/passphrases/API keys.
- Web UI has no third-party assets and no remote image loads.
- Retention removes old runs, raw/cache, audit, and orphan evidence.

## 5. Docs and release surface

- README quickstart commands work from a clean checkout.
- Privacy claims match code; limits are stated honestly.
- `docs/` links, sitemap, robots, JSON-LD, nav, and screenshots resolve.
- Version matches in `pyproject.toml`, `__init__.py`, `CITATION.cff`, docs, and lockfile.
- `CHANGELOG.md` has the release entry; the release sequence in `CONTRIBUTING.md` is current.
- Badges are not dead; CI/Pages URLs will work after publishing.
- No broken image paths; social preview/OG image exists.
- `tests/test_media_manifest.py` passes (assets and UI code fingerprint are current).

## 6. Fix loop

For every issue found:

1. Reproduce it with the smallest command or test.
2. Add a failing regression test (offline; `respx`/`TestClient`/Textual pilot).
3. Fix the root cause, not the symptom.
4. Run the targeted test, then the full suite.
5. Re-run the relevant audit section and record the evidence.

Do not downgrade a real bug to “known limitation” without documenting it and getting user
agreement.

## 7. Ship gate

Ship only when all are true:

- [ ] Full suite passes; lint/format/build clean.
- [ ] No open Critical/High security findings; Medium findings fixed or justified.
- [ ] Privacy invariants verified.
- [ ] Docs/links/screenshots valid.
- [ ] Version/changelog consistent.
- [ ] Explicit approval for this specific push/tag/release/publish.
- [ ] Commit hash and verification evidence recorded.

Report:

```
Commit: <hash>
Tests: <count> passed
Lint/format/build: clean
Security: <bandit/pip-audit results>
Privacy: <checked invariants>
Docs: <validation result>
Not shipped: <anything skipped and why>
```
