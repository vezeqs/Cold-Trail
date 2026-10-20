# AGENTS.md

Operating guide for contributors and coding agents working on `larpharvester`.

## Project

`larpharvester` is a production OSINT CLI with three interfaces over one
SQLite store:

- **CLI** (Typer + Rich) — `larpharvester <command>` (40 commands)
- **TUI** (Textual) — `larpharvester tui` (Dashboard / Pivot / Browse / Search / Tools / Cases)
- **Local web UI + JSON API** (FastAPI/uvicorn) — `larpharvester serve` (pages, JSON API,
  SSE-streamed pivot jobs, interactive identity graph, OSINT workbench, case management)

Python 3.11+, `uv` project, `src/` layout, async `httpx` sources, Pydantic v2,
SQLite with FTS5.

## Commands

```bash
uv sync                        # install deps into .venv
uv run pytest                  # full suite (no network; respx + TestClient + Textual pilot)
uv run pytest tests/test_web.py -q
uv run pytest tests/test_tui.py -q
uv run ruff check .            # lint
uv run ruff format --check .   # formatting
uv run larpharvester --help
uv run larpharvester tui                          # interactive terminal UI
uv run larpharvester serve --port 8765 --open     # local web UI
uv run larpharvester batch -f targets.txt          # multi-target pivots
uv run larpharvester recluster --run 3             # re-correlate stored profiles
uv run larpharvester export 3 --format stix -o bundle.json
python scripts/build_sites.py --fetch             # regenerate declarative corpus (pinned ref)
```

## Layout

```
src/larpharvester/
├── cli/            Typer commands (entry point: larpharvester.cli:app)
│   ├── _app.py       app, global callback (settings/audit/source sync), renderers
│   ├── collect.py    pivot, harvest, graph, watch
│   ├── query.py      profiles, posts, links, clusters, entities, runs, edges, search, timeline, history
│   ├── osint.py      sources, source list/test, dorks, analyze, archive, domain, ip, phone
│   ├── output.py     export, report, decrypt
│   ├── cases.py      case new/list/add/show, tag(s), note(s)
│   ├── ops.py        audit, doctor, prune, db
│   ├── breach.py     breach (HIBP / --all multi-provider), pwned (Pwned Passwords)
│   └── interfaces.py tui, serve
├── tui/app.py      Textual app: Dashboard / Pivot / Browse / Search / Tools / Cases
├── web/
│   ├── app.py        create_app(settings) -> FastAPI (pages, JSON API, jobs, SSE, graph, tools)
│   ├── templates/    Jinja2 templates (autoescape on)
│   └── static/       style.css, app.js (scope toggle, SSE stream, canvas graph)
├── store/          Store composed from mixins (public API: from larpharvester.store import Store)
│   ├── schema.py     DDL, FTS definitions, column migrations, SCHEMA_VERSION
│   ├── base.py       connection, PRAGMA setup, user_version gate, row helpers
│   ├── runs.py       runs, count_runs
│   ├── writes.py     checks/profiles/posts/links/clusters/entities/edges/history writes
│   ├── queries.py    read queries + FTS search + timeline
│   ├── caches.py     http_cache, raw, probe_cache, cursors
│   ├── cases.py      audit, cases, tags, notes
│   └── maintenance.py export_run, stats, check_stats, profile_hints, prune, vacuum, db_info
├── pivot.py        probing, variants, multi-hop expansion (depth), streaming on_result, persist_pivot()
├── harvest.py      profile + posts collection, follows
├── watch.py        monitoring loop, diffs, alerts
├── http.py         pacing, cache/ETag, circuit breaker, budget, WAF/bot-wall detection, proxy/Tor, replay
├── sources/        curated sources (subclass Source, @register) + declarative engine
├── data/sites.toml 453 generated site definitions (Sherlock v0.16.2, MIT)
├── correlate.py    pair scoring, Jaro-Winkler handle similarity, clusters, recluster_rows()
├── analysis.py     entity extraction (email/btc/eth/xmr/onion/pgp/ssh/matrix/…), language, timezone, stylometry
├── report.py       JSON/JSONL/CSV/GraphML/GEXF/DOT/HTML/Markdown/STIX/Maltego, redaction, encryption
├── breach.py       HIBP + HudsonRock + LeakCheck metadata, Pwned Passwords k-anonymity
├── domain.py       RDAP, DNS, crt.sh, SPF/DMARC, security.txt, favicon MMH3, takeovers, ASN, IP RDAP
├── domain.py, phone.py, wayback.py, dorks.py, alerts.py, avatars.py, variants.py, sites.py
├── config.py       Settings (TOML + env)
└── models.py       dataclasses
```

## Testing rules

- **Never hit the network in tests.** Sources: `respx`. Web: `fastapi.testclient.TestClient`.
  TUI: `App.run_test()` pilot (headless). Pivot/harvest workers are monkeypatched.
- Patching `SOURCES` must target where it is *used*, not where it is defined:
  `larpharvester.pivot.SOURCES`, `larpharvester.harvest.SOURCES`,
  `larpharvester.cli.collect.SOURCES`, `larpharvester.cli.osint.SOURCES`.
- Web tests seed a real SQLite file in `tmp_path` and build the app with
  `create_app(settings)`; do not use the default DB path.
- Async pivot jobs in the web app: poll `/api/jobs/{id}` until `done`/`error`
  (see `_wait_job` in `tests/test_web.py`).
- TUI worker tests: `await app.workers.wait_for_complete()` after `start_pivot()`;
  the final table is reconciled from the report even if streaming callbacks were missed.
- Every bug fix gets a regression test (`tests/test_regressions.py`).
- Source tests live in `tests/test_sources.py`, `tests/test_new_sources.py`, and
  `tests/test_sources_expanded.py`; engine upgrades in `tests/test_engine_upgrades.py`;
  multi-hop/batch/recluster in `tests/test_workflows.py`.

## Architecture rules

- **Public APIs are stable:** `from larpharvester.store import Store`,
  `from larpharvester.cli import app`, entry point `larpharvester.cli:app`.
- **Persistence goes through `pivot.persist_pivot(store, report)`** — CLI, TUI,
  and web all use it. Don't duplicate run-saving logic.
- **SQLite connections are thread-bound.** Each thread/request opens its own
  `Store`. The web app opens a short-lived Store per request (WAL makes this
  cheap); the TUI opens one per UI-thread refresh and one inside the pivot
  worker thread.
- **Pivots in the web app are background jobs** (`app.state.jobs`), serialized
  by `app.state.pivot_lock`; `POST /pivot` and `POST /api/pivot` return
  immediately with a job id. Each job accumulates `events` via the pivot
  `on_result` callback; `/api/jobs/{id}/stream` replays them as SSE `check`
  events and ends with a `done` event. The stream is replay-safe: connecting
  after completion still yields the full event list plus `done`.
- **The identity graph** (`/api/runs/{id}/graph`) is built by `_build_graph_payload`:
  profile nodes, entity nodes, follow-edge nodes, correlation/entity/follow edges.
  The canvas app.js runs a force simulation; keep node ids stable (`source:username`).
- **The tools workbench** (`/tools`, `POST /tools/run`) runs OSINT modules in-process
  and renders JSON; harvest/graph runs are persisted. Pwned Passwords input is never
  echoed back to the page.
- **Untrusted data:** harvested URLs may be malicious. Templates use the
  `| url` Jinja filter (http/https only); `report.py` blocks
  `javascript:`/`data:`/`vbscript:` hrefs. Keep it that way.
- **CSP:** `default-src 'self'; img-src 'self' data: https:; script-src 'self'`.
  Only external static assets (`static/app.js`); no inline scripts.
- **Source failures stay isolated:** `pivot._check` converts exceptions into
  `error`/`blocked` results. A broken source must never sink a pivot.
- **`Fetcher` sets `Accept` per call** (`get_json` → JSON, `get_text` → HTML).
  Do not add a global `Accept: application/json`; GitHub returns a 410
  API-retirement page for HTML requests with it.
- **Schema changes** must keep the `PRAGMA user_version` migration path working
  (current version: 3). Add columns via `store/schema.py::COLUMNS`.
- **Declarative corpus** entries that collide with curated source names are
  skipped at load time. `scripts/build_sites.py --fetch` pins a Sherlock git
  ref and stamps ref+sha256 into the file header; bump `PINNED_REF` deliberately.
- **No guard rails that weaken collection:** do not add artificial caps,
  allowlists, or "safety" filters that reduce source coverage or pivot breadth.
  Rate limiting/pacing is politeness, not restriction — keep it.
- **`breach.py` is lookup-only by design.** It may report breach metadata and
  exposure counts; it must never retrieve, dump, crack, or reconstruct
  credentials. `pwned_password` transmits only the 5-char SHA-1 prefix
  (k-anonymity) — never add the full hash, the password, or request logging
  that could capture them. Tests assert the privacy property; keep them.

## Web API surface

Pages: `/`, `/runs`, `/runs/{id}`, `/runs/{id}/export?format=…`, `/search`,
`/sources`, `/cases` (CRUD), `/tools` (workbench), `/pivot`, `/jobs/{id}`,
`/healthz`, `/api/docs`.

JSON: `/api/health`, `/api/stats`, `/api/runs`, `/api/runs/{id}`,
`/api/runs/{id}/graph`, `/api/search?q=`, `/api/sources`, `/api/jobs/{id}`,
`/api/jobs/{id}/stream` (SSE), `POST /api/pivot`.

Export formats: `json`, `jsonl`, `csv` (`&table=`), `graphml`, `gexf`, `dot`,
`html`, `md`, `stix`, `maltego`; `&redact=true` for redacted payloads.

## Gotchas

- Textual 2.x: nested `with` blocks in `compose()` are intentional (widget
  tree); `SIM117` is ignored for `tui/app.py`. `DataTable` needs
  `cursor_type = "row"` for Enter-to-select. Widgets showing arbitrary JSON
  must be created with `markup=False` — Rich's `escape()` does not cover
  JSON brackets like `["America/Los_Angeles"]` and Textual raises MarkupError.
- Starlette 1.x: `TemplateResponse(request, name, context)` — the old
  `(name, {"request": ...})` signature is gone.
- FastAPI form endpoints need `python-multipart` (declared dependency).
- `asyncio.create_task` must run on the event loop: web endpoints that start
  jobs are `async def`, not `def` (sync endpoints run in a threadpool).
- `Store.close()` before rendering templates is fine (data is materialized).
- `larpharvester --db PATH <cmd>` — global options come *before* the subcommand.
- **False-positive traps in HTML sources:** Substack serves a search page
  (`Search "x" on Substack`) for unknown handles — treat it as `not_found`.
  TikTok embeds `webapp.user-detail.statusCode` in SIGI; 10221/10202/10222 mean
  missing. Docker Hub returns `orgname` for organizations instead of `username`.
  Medium 403s non-browser clients (reported as `blocked`), so do not "fix" it
  by loosening the block detector.
- **Multi-hop expansion** (`pivot(depth=N)`) tracks a visited set so a target is
  never re-probed; each hop flips kind (email ↔ username). `on_result` fires for
  every check (including probe-cache hits) exactly once.
