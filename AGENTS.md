# AGENTS.md

## Project

`larpharvester` — Python 3.11+ OSINT CLI. `uv` project, `src/` layout, Typer CLI, async `httpx`
sources, SQLite storage, rich output.

## Commands

```bash
uv sync                      # install deps into .venv
uv run pytest                # full suite (pytest-asyncio auto mode, respx for HTTP)
uv run ruff check .          # lint
uv run ruff format --check . # formatting check
uv run larpharvester --help
python scripts/build_sites.py --fetch  # regenerate the declarative corpus (pinned Sherlock ref)
```

## Layout

- `src/larpharvester/sources/` — curated sources. Subclass `Source`, decorate with `@register`,
  implement `check()`, optionally `posts()`/`follows()`. Set `group`, `supports_posts`.
- `src/larpharvester/sources/declarative.py` — Sherlock-style site checks (`status_code`, `message`,
  `response_url`), loaded from `data/sites.toml`.
- `src/larpharvester/data/sites.toml` — 478 generated site definitions (MIT, Sherlock attribution).
- `src/larpharvester/correlate.py` — pair scoring, avatar/website/bio denylists, clusters.
- `src/larpharvester/pivot.py` — concurrent probing, variants, expansion, coverage, probe cache.
- `src/larpharvester/http.py` — pacing, cache/ETag, circuit breaker, budget, bot-wall detection,
  proxy/Tor, raw capture/replay.
- `src/larpharvester/store/` — `Store` composed from mixins: `schema.py` (DDL, migrations),
  `base.py` (connection, `user_version` gate, row helpers), `runs.py`, `writes.py`,
  `queries.py`, `caches.py` (http/probe/raw/cursors), `cases.py`, `maintenance.py`.
  Public API stays `from larpharvester.store import Store`.
- `src/larpharvester/analysis.py` — entities, language, timezone, stylometry.
- `src/larpharvester/report.py` — JSON/JSONL/CSV/GraphML/GEXF/DOT/HTML, redaction, encryption.
- `src/larpharvester/watch.py` / `alerts.py` — monitoring loop and notification sinks.
- `src/larpharvester/cli/` — Typer commands split by area: `_app.py` (app, callback,
  renderers), `collect.py` (pivot/harvest/graph/watch), `query.py` (stored-data reads),
  `osint.py` (sources/dorks/analyze/archive/domain/ip/phone), `output.py`
  (export/report/decrypt), `cases.py`, `ops.py`. Public API stays `larpharvester.cli:app`.

## Notes

- Tests must never hit the network; mock with `respx`. Source tests live in `tests/test_sources.py`
  and `tests/test_new_sources.py`.
- Source failures stay isolated: `pivot._check` converts exceptions into `error`/`blocked` results.
- `Fetcher` sets `Accept` per call (`get_json` → JSON, `get_text` → HTML). Do not add a global
  `Accept: application/json`; GitHub returns a 410 API-retirement page for HTML requests with it.
- New curated sources need: a module, a mocked test, a `group`, and `supports_posts` if applicable.
- Schema changes must keep `PRAGMA user_version` migration path working for existing DBs;
  current version is 3.
- Declarative corpus entries that collide with curated source names are skipped at load time.
- `scripts/build_sites.py --fetch` rebuilds `sites.toml` from a pinned Sherlock git ref
  (`PINNED_REF`); the header records the ref and sha256. Bump `PINNED_REF` deliberately.
- Tests that patch `SOURCES` must patch where it is *used*: `larpharvester.pivot.SOURCES`,
  `larpharvester.harvest.SOURCES`, `larpharvester.cli.collect.SOURCES` (harvest/graph
  validation), or `larpharvester.cli.osint.SOURCES` (source list/test).
