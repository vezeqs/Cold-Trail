# AGENTS.md

Operating guide for contributors and coding agents working on ColdTrail.

## Project

ColdTrail is a production OSINT CLI with three interfaces over one
SQLite store:

- **CLI** (Typer + Rich) — `coldtrail <command>` (46 top-level commands, 58 leaf commands)
- **TUI** (Textual) — `coldtrail tui` (Dashboard / Pivot / Browse / Search / Tools / Cases;
  `p` pivots the focused row, `h` harvests it, `d` diffs the two latest runs)
- **Local web UI + JSON API** (FastAPI/uvicorn) — `coldtrail serve` (pages, JSON API,
  SSE-streamed pivot jobs, interactive identity graph, OSINT workbench, run diffing,
  case dossiers, optional bearer/cookie auth, rate limiting)

Python 3.11+, `uv` project, `src/` layout, async `httpx` sources, Pydantic v2,
SQLite with FTS5.

## Commands

```bash
uv sync                        # install deps into .venv
uv run pytest                  # full suite (no network; respx + TestClient + Textual pilot)
uv run pytest --cov=coldtrail --cov-report=term-missing   # coverage (73% floor)
uv run pytest tests/test_web.py -q
uv run pytest tests/test_tui.py -q
uv run ruff check .            # lint
uv run ruff format --check .   # formatting
uv run mypy                    # typed core + store gate
uv run coldtrail --help
uv run coldtrail tui                          # interactive terminal UI
uv run coldtrail serve --port 8765 --open     # local web UI
uv run coldtrail batch -f targets.txt -j 4     # multi-target pivots (concurrent)
uv run coldtrail source health --live         # probe and record source status/latency
uv run coldtrail recluster --run 3             # re-correlate stored profiles (persists)
uv run coldtrail diff 3 4                      # compare two runs
uv run coldtrail source verify -s github       # replay contract fixtures offline
uv run coldtrail source verify --record -s github  # record fresh fixtures
uv run coldtrail ct example.com                # certificate-transparency search
uv run coldtrail export 3 --format stix -o bundle.json
python scripts/build_sites.py --fetch             # regenerate declarative corpus (pinned ref)
```

## Layout

```
src/coldtrail/
├── cli/            Typer commands (entry point: coldtrail.cli:app)
│   ├── _app.py       app, global callback (settings/audit/source sync), renderers
│   ├── collect.py    pivot, harvest, graph, watch
│   ├── query.py      profiles, posts, links, clusters, entities, runs, edges, search, timeline, history, diff
│   ├── osint.py      sources, source list/test, dorks, analyze, archive, domain, ip, phone, ct
│   ├── output.py     export, report, decrypt
│   ├── cases.py      case new/list/add/show/export, tag(s), note(s)
│   ├── ops.py        audit, doctor, prune, db
│   ├── breach.py     breach (HIBP / --all multi-provider), pwned (Pwned Passwords)
│   ├── evidence.py   evidence add/list/export/verify (content-addressed files)
│   ├── integrations.py integrations, run, ingest (external tools/imports)
│   ├── menu.py       interactive menu for common workflows
│   └── interfaces.py tui, serve
├── tui/app.py      Textual app: Dashboard / Pivot / Browse / Search / Tools / Cases / Help
├── web/
│   ├── app.py        create_app(settings) -> FastAPI (pages, JSON API, jobs, SSE, graph, tools, evidence)
│   ├── templates/    Jinja2 templates (autoescape on; help.html, run.html evidence)
│   └── static/       style.css, app.js (scope toggle, SSE stream, canvas graph, source filter)
├── store/          Store composed from mixins (public API: from coldtrail.store import Store)
│   ├── schema.py     DDL, FTS definitions, column migrations, SCHEMA_VERSION (7)
│   ├── base.py       connection, PRAGMA setup, user_version gate, row helpers
│   ├── runs.py       runs, count_runs
│   ├── writes.py     checks/profiles/posts/links/clusters/entities/edges/history writes
│   ├── queries.py    read queries + FTS search + timeline
│   ├── caches.py     http_cache, raw, probe_cache, cursors
│   ├── cases.py      audit, cases, tags, notes, attachments
│   └── maintenance.py export_run, stats, check_stats, profile_hints, prune, vacuum, db_info
├── pivot.py        probing, variants, multi-hop expansion (depth), streaming on_result, persist_pivot()
├── harvest.py      profile + posts collection, follows
├── watch.py        monitoring loop, diffs, alerts
├── http.py         pacing, cache/ETag, circuit breaker, budget, WAF/bot-wall detection, proxy/Tor, replay
├── sources/        curated sources (subclass Source, @register) + declarative engine
├── data/sites.toml 459 generated site definitions (Sherlock v0.16.2, MIT)
├── correlate.py    pair scoring, Jaro-Winkler handle similarity, clusters, recluster_rows(), diff_runs()
├── analysis.py     entity extraction (email/btc/eth/xmr/onion/pgp/ssh/matrix/…), language, timezone, stylometry
├── report.py       JSON/JSONL/CSV/GraphML/GEXF/DOT/HTML/Markdown/STIX/Maltego, redaction, encryption
├── breach.py       HIBP + HudsonRock + LeakCheck metadata, Pwned Passwords k-anonymity
├── contracts.py    source contracts, fixture recording, offline replay verification
├── domain.py       RDAP, DNS, crt.sh, SPF/DMARC, security.txt, favicon MMH3, takeovers,
│                   ASN/BGP, TLS certificate inspection, CT identity search
├── integrations.py external tool registry/runners/parsers + Maltego/SpiderFoot/theHarvester importers
├── evidence.py     content-addressed evidence store (SHA-256, dedupe, verify)
├── casework.py     merge_case_payload() shared by CLI and web case dossiers
├── domain.py, phone.py, wayback.py, dorks.py, alerts.py, avatars.py, variants.py,
│                   sites.py, websearch.py, company.py, security.py
├── config.py       Settings (TOML + env)
└── models.py       dataclasses

Dockerfile, docker-compose.yml, deploy/ (systemd units + env example),
tests/fixtures/contracts/ (recorded source fixtures)
```

## Testing rules

- **Never hit the network in tests.** Sources: `respx`. Web: `fastapi.testclient.TestClient`.
  TUI: `App.run_test()` pilot (headless). Pivot/harvest workers are monkeypatched.
- Patching `SOURCES` must target where it is *used*, not where it is defined:
  `coldtrail.pivot.SOURCES`, `coldtrail.harvest.SOURCES`,
  `coldtrail.cli.collect.SOURCES`, `coldtrail.cli.osint.SOURCES`.
- Web tests seed a real SQLite file in `tmp_path` and build the app with
  `create_app(settings)`; do not use the default DB path.
- Async pivot jobs in the web app: poll `/api/jobs/{id}` until `done`/`error`
  (see `_wait_job` in `tests/test_web.py`).
- TUI worker tests: `await app.workers.wait_for_complete()` after `start_pivot()`;
  the final table is reconciled from the report even if streaming callbacks were missed.
- Every bug fix gets a regression test (`tests/test_regressions.py`).
- Source tests live in `tests/test_sources.py`, `tests/test_new_sources.py`, and
  `tests/test_sources_expanded.py`; engine upgrades in `tests/test_engine_upgrades.py`;
  multi-hop/batch/recluster in `tests/test_workflows.py`; contract tests in
  `tests/test_contracts.py`; v0.5.0 core fixes in `tests/test_v050_core.py`;
  evidence in `tests/test_evidence.py`; external tools/importers in
  `tests/test_integrations.py`; case dossiers in `tests/test_casework.py`;
  live-investigation regressions in `tests/test_investigation_regressions.py`
  and `tests/test_twitch_regression.py`.
- **Contract fixtures** (`tests/fixtures/contracts/*.json`) are recorded real exchanges.
  Re-record with `coldtrail source verify --record -s <source>` and commit the JSON.
  Fixtures embed decompressed bodies; raw rows in SQLite are zlib-compressed, so always
  decompress when writing a recorder (see `contracts.record_contract`).

## Architecture rules

- **Public APIs are stable:** `from coldtrail.store import Store`,
  `from coldtrail.cli import app`, entry point `coldtrail.cli:app`.
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
- **Optional auth:** when `settings.web_token` is set, the `_auth` middleware requires
  `Authorization: Bearer`, `X-API-Key`, or the `coldtrail_token` cookie; `/healthz`,
  `/api/health`, `/login`, and `/static` stay public. HTML requests redirect to
  `/login`, API requests get 401. Keep `/healthz` public for container probes.
- **Rate limiting:** `POST /pivot`, `POST /api/pivot`, and `POST /tools/run` share a
  per-client sliding window (`RATE_LIMIT`/`RATE_WINDOW`, default 20/min) → HTTP 429.
- **Case dossiers:** `_case_payload(store, case)` merges all runs in a case (deduped
  profiles/posts/links/clusters/entities/edges) for `/cases/{name}/export`.
- **Run diff:** `correlate.diff_runs(store, a, b)` powers `coldtrail diff`,
  `GET /diff`, `GET /api/diff`, and the TUI `d` binding.
- **Untrusted data:** harvested URLs may be malicious. Templates use the
  `| url` Jinja filter (http/https only); `report.py` blocks
  `javascript:`/`data:`/`vbscript:` hrefs. Keep it that way.
- **CSP:** `default-src 'self'; img-src 'self' data:; script-src 'self'` (plus
  `base-uri 'none'`, `form-action 'self'`, `object-src 'none'`,
  `frame-ancestors 'none'`). `img-src` deliberately excludes remote origins —
  no remote image loads. Only local static assets (`static/app.js`); no inline
  scripts.
- **Source failures stay isolated:** `pivot._check` converts exceptions into
  `error`/`blocked` results. A broken source must never sink a pivot.
- **`Fetcher` sets `Accept` per call** (`get_json` → JSON, `get_text` → HTML).
  Do not add a global `Accept: application/json`; GitHub returns a 410
  API-retirement page for HTML requests with it.
- **Schema changes** must keep the `PRAGMA user_version` migration path working
  (current version: 7). Add columns via `store/schema.py::COLUMNS`.
  Schema v5 made `profiles.username` `COLLATE NOCASE`; `_rebuild_profiles()` dedupes
  and rebuilds old tables, and `_unique_indexes()` introspects `PRAGMA index_xinfo`
  instead of matching formatted SQL. Schema v6 added `posts.created_ts` (epoch
  seconds, backfilled) so timeline ordering and `--since/--until` run in SQL.
  Schema v7 added `source_health`.
- **Timeline ordering uses `created_ts`, not the display string.** Never sort
  `created_at` values lexicographically: ISO timestamps with different offsets
  do not sort chronologically. `Store.timeline()` returns the newest window in
  ascending order.
- **Source health is recorded, not inferred:** `source health --live` probes
  contract targets, upserts `source_health` (status, detail, latency), and the
  web `/sources` + `/api/sources` surfaces read that table.
- **Search scopes:** `Store.search()` (FTS5, snippet + prefix + source/username
  filters), `search_profiles()`, `search_entities()`, and `search_all()` back the
  CLI `--scope` flag and the web `scope` parameter. The default API response
  stays a list for backward compatibility.
- **Batch shares one `Fetcher`:** `coldtrail batch -j N` reuses a single fetcher
  so pacing, budget, and circuit state span the whole batch; persistence is
  serialized through one Store connection.
- **Evidence is content-addressed:** `evidence.add_evidence()` hashes bytes,
  writes `<db dir>/evidence/<sha[:2]>/<sha>` atomically, and inserts an
  `attachments` row. Never store evidence only in the DB; `evidence verify`
  must be able to detect missing/corrupted blobs.
- **External tools run via argument vectors, never a shell.** `integrations.run_tool`
  validates the target (`validate_target` rejects leading `-`, NUL, and newlines)
  before executing, then uses
  `subprocess.run(list, shell=False, timeout=..., cwd=tempdir)` and preserves
  the environment (`HOME`, proxies, tokens) with `NO_COLOR`/`TERM=dumb` overrides.
  Username/social wrappers: sherlock, maigret, naminter, social-analyzer, blackbird
  (via otinstaller), instaloader, twscrape. Import-only: SpiderFoot and Maltego.
  Missing binaries raise `ToolUnavailable` with an install hint.
- **Importers normalize to models:** Maltego CSV → profiles/links/entities;
  SpiderFoot JSON → entities/profiles; theHarvester JSON → entities; generic JSON
  → profiles/entities. Add a new format to `INGEST_FORMATS` + `detect_format` + tests.
- **Menus:** commands are grouped with `rich_help_panel=` (Start here / Collect /
  Query / Intel / Integrations / Evidence / Casework / Output / Interfaces /
  Operations). `app.add_typer(..., rich_help_panel=...)` groups sub-apps. The
  interactive `menu` command reuses library functions, not Typer callbacks.
- **Case dossiers** go through `casework.merge_case_payload()`; CLI `case export`
  and web `/cases/{name}/export` must stay identical.
- **Declarative corpus** entries that collide with curated source names are
  skipped at load time. `scripts/build_sites.py --fetch` pins a Sherlock git
  ref and stamps ref+sha256 into the file header; bump `PINNED_REF` deliberately.
- **Privacy defaults are part of the contract:** `keep_raw=False`,
  `avatar_hash=False`, DB/WAL/SHM/evidence/exports `0600`, evidence dirs
  `0700`, Tor via `socks5h://`, email targets hashed with
  `utils.sensitive_cache_key`, no telemetry, and non-loopback `serve` requires
  a token unless `--allow-unauthenticated` is explicit. Do not regress these
  without updating README/SECURITY/privacy docs and tests.
- **No guard rails that weaken collection:** do not add artificial caps,
  allowlists, or "safety" filters that reduce source coverage or pivot breadth.
  Rate limiting/pacing is politeness, not restriction — keep it.
- **`breach.py` is lookup-only by design.** It may report breach metadata and
  exposure counts; it must never retrieve, dump, crack, or reconstruct
  credentials. `pwned_password` transmits only the 5-char SHA-1 prefix
  (k-anonymity) — never add the full hash, the password, or request logging
  that could capture them. Tests assert the privacy property; keep them.

## Web API surface

Pages: `/`, `/runs`, `/runs/{id}`, `/runs/{id}/export?format=…`, `/search`
(`scope=posts|profiles|entities|all`, `prefix`, `source`, `username`),
`/sources` (with recorded health), `/cases` (CRUD), `/tools` (workbench),
`/pivot`, `/jobs/{id}`, `/help`, `/login`, `/logout`, `/evidence/{id}`,
`/healthz`, `/api/docs`, `/api/openapi.json`.

JSON: `/api/health`, `/api/stats`, `/api/runs`, `/api/runs/{id}`,
`/api/runs/{id}/graph`, `/api/diff?a=&b=`,
`/api/search?q=&scope=&prefix=&source=&username=`, `/api/sources` (includes
`health`), `/api/jobs/{id}`, `/api/jobs/{id}/stream` (SSE), `POST /api/pivot`,
`/api/evidence/{id}`.

Auth (when `web_token` is set): bearer/`X-API-Key`/cookie; `/login` page sets the cookie.

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
- `coldtrail --db PATH <cmd>` — global options come *before* the subcommand.
- **False-positive traps in HTML sources:** Substack serves a search page
  (`Search "x" on Substack`) for unknown handles — treat it as `not_found`.
  TikTok embeds `webapp.user-detail.statusCode` in SIGI; 10221/10202/10222 mean
  missing. Docker Hub returns `orgname` for organizations instead of `username`.
  Medium 403s non-browser clients (reported as `blocked`), so do not "fix" it
  by loosening the block detector.
- **Multi-hop expansion** (`pivot(depth=N)`) tracks a visited set so a target is
  never re-probed; each hop flips kind (email ↔ username). `on_result` fires for
  every check (including probe-cache hits) exactly once.
- **Shared fetchers:** `http.shared_fetcher(settings, store, fetcher)` reuses a
  caller-provided Fetcher or opens one. `pivot`, `harvest`, `collect_follows`, and
  `watch` all accept `fetcher=...` so budgets/pacing/circuit state span a whole
  watch cycle or pivot+harvest phase. Never open a second Fetcher inside those flows.
- **Key material:** SSH fingerprints use OpenSSH `SHA256:` format (`utils.ssh_fingerprint`);
  GPG key IDs/emails come from forge APIs. These become `ssh_key`/`pgp_fingerprint`
  entities and feed the 0.95 cryptographic-identifier signal.
- **EXIF:** `avatars.extract_image_metadata` returns camera/software/author/GPS fields;
  stored under `profile.extra["avatar_meta"]`, extracted as entities, and compared by
  `_avatar_meta_signal` (serial/capture-time 0.4, author 0.3).
- **Reports show calibrated confidence** (`correlate.calibrate_probability`) next to the
  additive score. Do not replace stored additive scores — tests and thresholds rely on them.
- **Deployment:** Dockerfile builds a wheel with `uv` and installs into a non-root
  python:3.12-slim image (`/data` volume, port 8765, `/healthz` healthcheck).
  `docker-compose.yml` has an optional `tor` profile (`socks5h://tor:9050`).
  systemd units in `deploy/` are hardened (`ProtectSystem=strict`, empty capability set).
  OCI builds ignore `HEALTHCHECK` (podman warning); that is expected.
- **Bluesky:** the public AppView does NOT implement `com.atproto.repo.listRecords`
  (HTTP 501). Harvests must use `app.bsky.feed.getAuthorFeed` with `actor`/`cursor`.
- **Twitch:** existence requires `<meta property="og:profile:username">` matching the
  handle. Missing handles return HTTP 200 with a generic "Twitch" shell — never trust
  the title alone, and never store the "streams live on Twitch!" template as a bio.
- **Declarative `web.*` profiles are page templates, not user text.** `_untrusted_text()`
  excludes their bio/display-name/mentions/entities/avatar/EXIF from correlation, and
  `profile_entities()` returns [] for them. `_page_rejected()` rejects challenge,
  landing, consent, and not-found titles (HTTP 200 pages are often generic).
  `scripts/build_sites.py` filters search/availability endpoints (`/search`, `?q=`,
  `?username=`, `usernameExists`, …) from the corpus.
- **Expansion is structured-evidence-only:** `discovered_usernames` trusts a profile's
  username only for username-kind sources; email sources contribute only
  accounts/proofs/logins/handle-history/NIP-05. `discovered_emails` reads only
  `extra.email`, `extra.public_email`, and GPG UID emails — never bio text. This prevents
  common local-parts (`simon@…` → `simon`) from pivoting into strangers.
- **Same-platform pairs never correlate** (`correlate` skips `a.source == b.source`),
  because shared default avatars and similar handles on one platform are usually
  different people.
- **`diff_runs` serializes record types separately** (profiles/entities vs links);
  never reuse the profile serializer for links.
- **`ct` uses `crtsh_identities(..., strict=True)`** so a 502/503 from crt.sh is a
  clear error (exit 2), not an empty result table.
- **Speed invariants (0.5.2):**
  - `Fetcher` never retries `ConnectError`/`ConnectTimeout` (DNS/refused failures are
    permanent for probes); `TimeoutException` honours the per-call `retries` argument.
  - Declarative checks call `fetcher.get(..., timeout=min(settings.timeout, 8), retries=0)`
    so one dead host cannot stall a 470-site pivot for 30s.
  - `Fetcher._build` sniffs JSON from raw bytes (`content[:1]`), never `response.text`;
    text decoding is capped at `MAX_TEXT`, and HTML cache bodies at `CACHE_HTML_MAX`
    (256 KB). Do not reintroduce full-body `response.text` access.
  - Default `concurrency` is 24 (per-host pacing still 5 rps). Benchmarks: 471-check web
    pivot ~22s cold / ~15s warm; curated ~4s cold / ~2s warm.
  - `web.*` avatars are never downloaded/hashed (site logos, excluded from correlation).
  - `pivot` renders found-only by default; `--all-checks` shows every check. JSON/JSONL
    paths are unaffected and must remain complete.
- **Evidence (0.6.0):** blobs live at `<db dir>/evidence/<sha[:2]>/<sha>`; the
  `attachments` table stores metadata only. `evidence verify` must stay able to
  detect missing/tampered blobs. Moving a database means moving `evidence/` too.
- **External tool runners (0.6.0):** `integrations.run_tool` uses an argument
  vector (`shell=False`), a temp cwd, an inherited environment plus
  `NO_COLOR`/`TERM=dumb`, and a timeout. Missing binaries raise `ToolUnavailable`
  with an install hint. Never call a blocking runner directly in an async web
  handler — use `asyncio.to_thread`.
- **Import formats:** add new formats to `INGEST_FORMATS`, `detect_format`, and
  `tests/test_integrations.py`. Maltego alias→alias rows become links; alias→typed
  rows become entities.
- **Web checkbox defaults:** checked HTML checkboxes send `"true"`, unchecked send
  nothing. A route parameter for a checked-by-default checkbox must default to
  `False`, otherwise unchecking is a no-op (fixed for avatar hashing, tool save,
  and ingest save).
- **Table CSS:** never set `display: block` on `<table>`; it makes `tbody` rows
  shrink-wrap to content even though the table box is full width. Use
  `.panel { overflow-x: auto }` for wide tables.
- **Menu grouping:** `@app.command(rich_help_panel="…")` and
  `app.add_typer(..., rich_help_panel="…")` build the categorized help. Keep new
  commands in a panel; otherwise they appear under a generic "Commands" panel.
- **TUI shortcuts:** `1`–`7` switch tabs via `Binding(..., show=False)`; the
  Footer only shows q/r/p/h/d so it stays readable at 80 columns.
