# Contributing to ColdTrail

Thanks for helping. ColdTrail is a local-first OSINT toolkit; correctness,
privacy, and reproducible tests matter more than feature volume.

## Setup

```bash
git clone https://github.com/slopmanufacturer/coldtrail
cd coldtrail
uv sync
uv run coldtrail doctor --offline
```

Python 3.11+, `uv`, and a `src/` layout.

## Checks

Run these before opening a pull request:

```bash
uv run ruff check .
uv run ruff format --check .
uv run pytest -q
uv build --wheel
```

Tests **never hit the network**. Use `respx` for HTTP sources,
`fastapi.testclient.TestClient` for the web app, and Textual's `run_test()`
pilot for the TUI. If you need a live probe, do it manually and do not commit
the test.

## Repository map

```
src/coldtrail/
  cli/        Typer commands and shared renderers
  tui/        Textual app
  web/        FastAPI app, templates, static assets
  store/      SQLite schema, writes, queries, migrations, maintenance
  sources/    curated sources + declarative engine
  pivot.py    probing, variants, expansion, persistence
  harvest.py  profiles, posts, follows
  correlate.py pair scoring, clusters, diff
  report.py   JSON/CSV/GraphML/GEXF/DOT/HTML/Markdown/STIX/Maltego
  http.py     pacing, cache, retries, circuit breaker, Tor/proxy
  evidence.py content-addressed evidence
tests/        offline test suite + contract fixtures
docs/         GitHub Pages site (sitemap, robots, privacy page)
```

See [AGENTS.md](AGENTS.md) for the detailed architecture and invariants.

## Adding a source

1. Subclass `Source`, set `name`, `label`, `kind`, `group`, and implement
   `async def check(fetcher, target)`.
2. Return `self.ok(...)`, `self.missing(...)`, `self.blocked(...)`, or
   `self.failed(...)` — never raise for a normal source outcome.
3. Decorate with `@register` and import the module in `sources/__init__.py`.
4. Add a contract in `contracts.py` and a recorded fixture under
   `tests/fixtures/contracts/`.
5. Add `respx` tests for found, missing, and blocked/error paths.

```bash
uv run coldtrail source verify --record -s mysource
uv run coldtrail source verify -s mysource
```

## Privacy invariants

Do not merge changes that break these:

- **No telemetry** or hidden network calls. The only outbound requests are
  user-initiated sources/tools.
- **Raw HTTP bodies stay opt-in** (`keep_raw=False` by default).
- **Sensitive identifiers never enter cache/raw keys** — use
  `utils.sensitive_cache_key()` for emails and other sensitive targets.
- **API keys stay out of URLs** where the provider supports a header; redact
  them from local cache keys where it does not.
- **Owner-only files** — DB/WAL/SHM and evidence are `0600`, evidence dirs and
  exports are `0700`/`0600`.
- **Tor uses `socks5h`** so DNS does not leak.
- **Web UI stays local-first** — bind `127.0.0.1`, optional token, HMAC cookie,
  CSP/no-referrer/no-store, no third-party assets.
- **Breach features are metadata-only**; Pwned Passwords stays k-anonymous.

## Commit and review

- One logical change per commit; imperative subject, reason in the body.
- Add a regression test for every bug fix.
- Do not include credentials, `.env` files, databases, or generated artifacts.
- Report security issues privately via [SECURITY.md](SECURITY.md), not a public
  issue.
