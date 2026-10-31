# AGENTS.md

Operating guide for contributors and coding agents working on ColdTrail.

## What this is

ColdTrail is a local-first OSINT toolkit that pivots usernames and emails across
482 public sources, harvests profiles and posts into one SQLite database, and
correlates identities into evidence-grade dossiers. It ships three interfaces
over the same store: a Typer CLI, a Textual TUI, and a FastAPI web UI/JSON API.
Python 3.11+, `uv`, `src/` layout, async `httpx`, Pydantic v2, SQLite + FTS5.
The CLI exposes 48 top-level commands and 61 leaf commands.

The public APIs are stable: `from coldtrail.store import Store`,
`from coldtrail.cli import app`, entry point `coldtrail.cli:main` (a wrapper that
turns `ConfigError`/`StoreError` into one line and exit 2; `app` stays the
Typer object).

## Which entry point answers which question

| Question | Entry point |
| --- | --- |
| Does a handle exist across sources, and how do the hits correlate? | `coldtrail pivot`, `pivot.pivot()` |
| What did one account post? | `coldtrail harvest`, `harvest.harvest()` |
| Who follows whom? | `coldtrail graph`, `harvest.collect_follows()` |
| What changed between two runs? | `coldtrail diff`, `correlate.diff_runs()` |
| What is stored and how do I search it? | `coldtrail profiles/posts/links/clusters/entities/search/timeline`, `Store.*` |
| What is in the config right now? | `coldtrail config --json`, `Settings.describe()` |
| What shape is a `--json` payload? | `coldtrail schema <name>`, `coldtrail/schemas.py` |
| Can I import/export this into another tool? | `coldtrail export/report/ingest`, `report.py`, `integrations.py` |
| What is broken right now? | `coldtrail doctor`, `coldtrail source health --live` |

## Commands

```bash
uv sync                                  # install into .venv
uv run pytest                            # full suite (no network)
uv run pytest --cov=coldtrail --cov-report=term-missing   # 73% floor
uv run ruff check . && uv run ruff format --check .
uv run mypy                              # typed core + store gate
uv run coldtrail doctor --offline        # DB, privacy posture, keys
uv run coldtrail config --json           # effective settings + provenance
uv run coldtrail schema --list           # JSON Schema contracts
uv run coldtrail tui                     # terminal UI
uv run coldtrail serve --port 8765 --open
uv run coldtrail batch -f targets.txt -j 4
uv run coldtrail source health --live
uv run coldtrail source verify -s github # replay fixtures offline
uv run coldtrail source verify --record -s github
uv run coldtrail diff 3 4 --format html -o diff.html
uv run coldtrail export 3 --format sarif -o findings.sarif
uv run coldtrail export 3 --format stix -o bundle.json
python scripts/build_sites.py --fetch    # regenerate corpus (pinned ref)
uv run --with playwright python scripts/capture_media.py  # regenerate README proof
```

`coldtrail --db PATH <cmd>`: global options come **before** the subcommand.

## Layout

```
src/coldtrail/
├── cli/            Typer commands (entry point: coldtrail.cli:main)
│   ├── _app.py       app, global callback (settings/audit/source sync), renderers
│   ├── collect.py    pivot, batch, harvest, graph, watch, recluster
│   ├── query.py      profiles, posts, links, clusters, entities, runs, edges,
│   │                 search, timeline, history, diff
│   ├── osint.py      sources, source list/test/health/verify, dorks, analyze,
│   │                 archive, domain, ip, phone, ct, websearch
│   ├── output.py     export, report, decrypt
│   ├── cases.py      case new/list/add/show/export, tag(s), note(s)
│   ├── ops.py        config, schema, audit, doctor, prune, db
│   ├── breach.py     breach (HIBP / --all), pwned (Pwned Passwords)
│   ├── evidence.py   evidence add/list/export/verify
│   ├── integrations.py integrations, run, ingest
│   ├── menu.py       interactive menu
│   └── interfaces.py tui, serve
├── tui/app.py      Textual app: Dashboard / Pivot / Browse / Search / Tools / Cases / Help
├── web/
│   ├── app.py        create_app(settings) -> FastAPI (pages, jobs, SSE, tools, evidence)
│   ├── helpers.py    constants, filters, Job/PivotRequest, graph payload, EXPORTERS
│   ├── api_routes.py JSON API registration (runs, graph, search, sources, health)
│   ├── case_routes.py cases, tags, and notes registration
│   ├── templates/    Jinja2 (autoescape on; `| url` for untrusted links)
│   └── static/       style.css, app.js (scope toggle, SSE, canvas graph, filter)
├── store/          Store composed from mixins
│   ├── schema.py     DDL, FTS, COLUMNS, SCHEMA_VERSION (7)
│   ├── base.py       connection, PRAGMAs, migrations, row helpers
│   ├── runs.py       runs, count_runs
│   ├── writes.py     checks/profiles/posts/links/clusters/entities/edges/history
│   ├── queries.py    reads, FTS search, timeline
│   ├── caches.py     http_cache, raw, probe_cache, cursors
│   ├── cases.py      audit, cases, tags, notes, attachments
│   └── maintenance.py export_run, stats, prune, vacuum, db_info
├── pivot.py        probing, variants, multi-hop expansion, persist_pivot()
├── harvest.py      profile + posts collection, follows
├── watch.py        monitoring loop, diffs, alerts
├── http.py         pacing, cache/ETag, circuit breaker, budget, WAF detection, Tor
├── sources/        curated sources (@register) + declarative engine
├── data/sites.toml 459 generated site definitions (Sherlock v0.16.2, MIT)
├── correlate.py    pair scoring, clusters, recluster_rows(), diff_runs()
├── analysis.py     entities, language, timezone hints, stylometry
├── report.py       JSON/JSONL/CSV/GraphML/GEXF/DOT/HTML/Markdown/STIX/SARIF/
│                   Maltego, redaction, encryption, HTML diff
├── schemas.py      JSON Schema contracts for --json payloads
├── breach.py       HIBP + HudsonRock + LeakCheck metadata, Pwned Passwords
├── contracts.py    source contracts, fixture recording, offline replay
├── domain.py       RDAP, DNS, crt.sh, SPF/DMARC, security.txt, favicons,
│                   takeovers, ASN/BGP, TLS, CT identity search
├── integrations.py external tool registry/runners/parsers + importers
├── evidence.py     content-addressed evidence (SHA-256, dedupe, verify)
├── casework.py     merge_case_payload() shared by CLI and web dossiers
├── domain.py, phone.py, wayback.py, dorks.py, alerts.py, avatars.py, variants.py,
│                   sites.py, websearch.py, company.py, security.py
├── config.py       Settings (TOML + env), provenance, redaction
└── models.py       dataclasses
```

## Invariants (testable)

1. **Tests never touch the network.** `respx` for sources, `TestClient` for web,
   `App.run_test()` for TUI, monkeypatched workers for pivot/harvest.
   `tests/conftest.py` blocks `socket.connect` for every test; a test that really
   needs a socket must carry `@pytest.mark.network`.
2. **Timestamps sort chronologically.** Never `sorted(..., key=created_at)` or
   `min()/max()` on display strings. Use `utils.epoch_seconds()` or the stored
   `created_ts`. This applies to SQL, reports, harvest windows, watch, and
   `analysis.infer_timezone` (bin in UTC, not in the source offset).
3. **Untrusted text is escaped in the right context.** HTML: Jinja autoescape or
   `html.escape`. XML attributes: `quoteattr`, not `escape`. Markdown tables:
   `_md_cell`. DOT: `_dot_escape`. URLs: `_safe_url`/`report.link` (http/https only).
   CSV: `report._csv_cell`, or a harvested `=HYPERLINK(...)` executes on open.
4. **The cache never hides a failure.** A blocked/WAF page must not be written to
   `http_cache`; a cache hit is re-classified before being returned. Cache keys
   vary by `Accept`, and cached bodies decode with their stored charset.
5. **Evidence is content-addressed and path-safe.** Hash the bytes you read,
   require 64 lowercase hex characters before joining a blob path, and keep
   `evidence verify` able to detect missing/tampered blobs. `source_path` input
   is streamed (`_store_blob_from_path`), never read into RAM.
6. **Privacy defaults do not regress:** `keep_raw=False`, `avatar_hash=False`,
   DB/WAL/SHM/evidence/exports `0600`, evidence dirs `0700`, Tor `socks5h://`,
   email targets hashed with `sensitive_cache_key`, no telemetry, and non-loopback
   `serve` requires a token unless `--allow-unauthenticated` is explicit.
   Exports are created 0600 by `os.open`, not by a chmod after the write.
7. **Secrets never reach output.** `doctor`/`config` redact proxy userinfo and
   key values; `_redact_argv` covers `--token`, `--passphrase`, `--api-key`,
   `--secret`, `--key`, and `--proxy`. `redact_url_credentials` never raises.
8. **Persistence goes through `pivot.persist_pivot(store, report)`.** CLI, TUI,
   and web must not duplicate run-saving logic.
9. **SQLite connections are thread-bound.** Each thread/request opens its own
   `Store`; the web app opens a short-lived Store per request, the TUI opens one
   per refresh and one inside the worker thread.
10. **Source failures stay isolated.** `pivot._check` converts exceptions into
    `error`/`blocked` results; a broken source must never sink a pivot.
11. **The declarative corpus is pinned.** `scripts/build_sites.py --fetch` pins a
    Sherlock ref and stamps ref+sha256; bump `PINNED_REF` deliberately.
12. **`breach.py` is lookup-only.** No credential retrieval, cracking, or full
    hash transmission; Pwned Passwords sends only the 5-char SHA-1 prefix.
13. **No guard rails that weaken collection.** Do not add artificial caps or
    allowlists that reduce coverage. Rate limiting/pacing is politeness, not
    restriction. (`MAX_RETRY_AFTER` caps a *sleep*, not a source.)
14. **Public API and schema paths stay compatible.** Add columns via
    `store/schema.py::COLUMNS` and keep the `PRAGMA user_version` migration path
    working (current: 7).
15. **The web UI is Host/Origin gated.** Loopback names (plus `testserver` in
    tests) are accepted unless `settings.allow_remote_host`; a non-GET request
    with a foreign `Origin` or a cross-site `Sec-Fetch-Site` is 403. `serve`
    sets `allow_remote_host` only for a deliberate non-loopback bind.
16. **A raw socket must validate and pin.** `tls_cert_info` resolves through
    `security.resolve_public_ips` and connects to the validated address; with
    `--proxy`/`--tor` it refuses instead of leaking a direct connection.
17. **Config is closed and typed.** `Settings.load` rejects unknown keys and
    wrong types (`ConfigError`); every `COLDTRAIL_*` value is parsed through
    `_env_number`/`_env_bool` so a typo is a one-line error, not a traceback.

## Sharp edges (each one already produced a bug here)

- **Textual 8 is the runtime.** `Static.renderable` was removed; tests use
  `_static_text()` (`renderable` → `content` → `render()`). The TUI source uses
  `Static.update()`. Keep both test paths working if the dependency floor moves.
- **`Fetcher` cache ordering:** `_cache_put` must run *after* `_looks_blocked`.
  Otherwise a 200 Cloudflare/challenge page is replayed as a valid profile.
- **`Fetcher` cache identity:** `get_json` and `get_text` on the same URL must not
  share a row. The HTTP cache key includes `Accept`; raw/replay keys stay URL-only
  so contract fixtures still match.
- **Cached charset:** `_from_cache` must decode with the stored `charset`, not
  UTF-8 unconditionally.
- **Redirect SSRF:** `follow_redirects=True` means the final URL must be checked
  again (`is_public_host(..., resolve=False)`); a public URL can redirect to
  `127.0.0.1`.
- **`is_public_host` returns `True` on DNS failure** and the initial check is
  still a TOCTOU for proxied clients. Direct HTTP connections are pinned
  (`_PinnedTransport`) and the TLS probe resolves once; a proxy resolves the name,
  so the proxy is the trust boundary there. Do not turn a resolver outage into a
  block.
- **`resolve=False`** is used by Mastodon/Nostr/domain/avatar probes to keep
  offline tests deterministic. The web layer calls `ensure_public_target()` first;
  the CLI exposes `--allow-private-targets`.
- **XML attributes:** `xml.sax.saxutils.escape()` does not escape `"`. Use
  `quoteattr`; otherwise GraphML/GEXF is invalid XML for a handle with a quote.
- **`add_evidence`:** hash `data`, not the source path a second time. Two reads
  are a TOCTOU and can store bytes under the wrong digest.
- **Evidence paths:** a DB `sha256` is a path component. Validate
  `^[0-9a-f]{64}$` before joining; `../../…` must be rejected, not resolved.
- **SQLite creation:** wrap `connect`/`mkdir` in `umask(0o077)`. A chmod after
  connect leaves a `0644` window for the DB and WAL/SHM.
- **`report.to_html`/`to_markdown` timelines** used display-string sorting; use
  `_post_order`/`epoch_seconds`.
- **`harvest`/`watch` windows** used `min()/max()` on `created_at`; use epoch
  order for both the tombstone boundary and the incremental cursor.
- **`analysis.PATTERNS["telegram"]`** must not match Matrix IDs
  (`@alice:matrix.org`); the trailing `(?!:)` is load-bearing.
- **`report.to_dot`** must default a missing score to `0`, or emits `weight=None`.
- **`report._md_cell`** must escape `|` and collapse newlines, or harvested text
  breaks the table.
- **Empty targets:** `Form(min_length=1)` accepts `" "`. Validate after
  `.strip()` in `pivot()`, `harvest()`, `collect_follows()`, and web routes.
- **Corrupt JSON rows:** use `utils.json_loads(value, default)`; one bad
  `extra_json` must not crash a query.
- **Audit hook:** catch `sqlite3.Error` as well as `OSError`/`ValueError`, or a
  corrupt DB prints a traceback before every command.
- **Case names:** `Store.create_case` rejects empty/whitespace and >120 chars;
  web routes rely on that ValueError for a 400.
- **`search` FTS:** tokens are quoted; do not interpolate raw user input into
  `MATCH`. The web page shows a generic `invalid query`, never the exception.
- **`Fetcher` sets `Accept` per call.** Do not add a global
  `Accept: application/json`; GitHub returns a 410 retirement page for HTML
  requests with it.
- **Source false positives:** Substack serves a search page for unknown handles;
  TikTok embeds status codes; Docker Hub returns `orgname` for orgs; Medium 403s
  non-browser clients (report `blocked`, do not loosen the detector).
- **Multi-hop expansion** tracks a visited set; each hop flips kind
  (email ↔ username); `on_result` fires once per check, including cache hits.
- **Shared fetchers:** `http.shared_fetcher(settings, store, fetcher)` reuses a
  caller-provided Fetcher. Never open a second one inside pivot+harvest/watch.
- **Reports show calibrated confidence** next to additive scores; do not replace
  stored additive scores (tests and thresholds rely on them).
- **Declarative `web.*` profiles are page templates, not user text.**
  `_untrusted_text()` excludes bio/display-name/mentions/entities/avatar/EXIF
  from correlation; `profile_entities()` returns `[]` for them.
- **Expansion is structured-evidence-only.** Email sources contribute only
  accounts/proofs/logins/handle-history/NIP-05, never bio-derived emails.
- **Same-platform pairs never correlate** (`a.source == b.source` skipped).
- **`diff_runs` serializes record types separately**; never reuse the profile
  serializer for links.
- **`ct` uses `crtsh_identities(..., strict=True)`** so a 502/503 is a clear
  error (exit 2), not an empty table.
- **Speed invariants:** no retry on `ConnectError`/`ConnectTimeout`; declarative
  checks use `timeout=min(settings.timeout, 8)`, `retries=0`; `_build` sniffs
  JSON from raw bytes, caps text at `MAX_TEXT`, HTML cache at `CACHE_HTML_MAX`
  (256 KB); default concurrency 24.
- **`web.*` avatars are never downloaded/hashed** (site logos, not user images).
- **Evidence lives beside the DB.** Moving a database means moving `evidence/`.
- **External tools run via argument vectors**, `shell=False`, temp cwd, inherited
  environment plus `NO_COLOR`/`TERM=dumb`, timeout. Never call a blocking runner
  directly in an async web handler — use `asyncio.to_thread`.
- **Web checkbox defaults:** checked boxes send `"true"`, unchecked send nothing;
  a checked-by-default route parameter must default to `False`.
- **Table CSS:** never `display: block` on `<table>`; use `.panel { overflow-x: auto }`.
- **Menu grouping:** keep new commands in a `rich_help_panel`; otherwise they
  appear under a generic "Commands" panel.
- **TUI shortcuts:** `1`–`7` switch tabs; the Footer shows only q/r/p/h/d.
- **Textual `compose()` nested `with` blocks are intentional** (`SIM117` ignored
  for `tui/app.py`); `DataTable` needs `cursor_type="row"`; JSON widgets need
  `markup=False` (Rich markup does not escape `["America/Los_Angeles"]`).
- **Starlette 1.x** uses `TemplateResponse(request, name, context)`.
- **FastAPI forms** need `python-multipart` (declared).
- **`asyncio.create_task`** must run on the event loop; web job endpoints are
  `async def`, not `def`.
- **Deployment:** Dockerfile builds a wheel with `uv` into a non-root
  python:3.12-slim image (`/data`, 8765, `/healthz` healthcheck). Compose has an
  optional `tor` profile. systemd units are hardened. OCI builds ignore
  `HEALTHCHECK` (podman warning) — expected.
- **Bluesky:** the AppView does not implement `com.atproto.repo.listRecords`
  (501); use `app.bsky.feed.getAuthorFeed`.
- **Twitch:** existence requires `og:profile:username` matching the handle; a
  missing handle returns a 200 generic shell.
- **TUI worker tests:** `await app.workers.wait_for_complete()` after
  `start_pivot()`; the final table is reconciled from the report.
- **Contract fixtures** (`tests/fixtures/contracts/*.json`) embed decompressed
  bodies; raw rows in SQLite are zlib-compressed. Re-record with
  `coldtrail source verify --record -s <source>`.
- **`_PinnedTransport` must not rewrite a URL another layer owns.** respx swaps
  the httpcore pool's `handle_async_request`; `_owns_routing()` detects that and
  passes the request through untouched. Remove that check and every mocked
  source test matches on an IP instead of a hostname.
- **The redirect check resolves DNS only when the host changed** (`resolve=True`)
  and falls back to `resolve=False` for the unchanged case, so literal private
  IPs stay blocked without a DNS lookup on every response.
- **`Retry-After` above `MAX_RETRY_AFTER` is a refusal, not a sleep.** A source
  asking for an hour must fail the check, not stall `asyncio.gather`.
- **Suffix matching needs a label boundary.** `_domain_matches` (not `endswith`)
  for CT subdomains, MX providers, and takeover CNAMEs; `notexample.com` is not
  a subdomain of `example.com`.
- **`tls_cert_info` takes `settings` and refuses under `--proxy`/`--tor`.** It is
  a raw socket, so it cannot use the proxy; returning `None` is the honest
  answer, and `lookup_domain` records `tls_skipped`.
- **`Settings.load` is a closed schema.** Unknown keys, `[section]` tables, and
  wrong types raise `ConfigError`; add new settings to `ENV_VARS`, `_coerce`
  type sets, and the README table together.
- **`Store.__init__` raises `StoreError`, and `run_cli` maps it to exit 2.**
  Tests that invoke `app` directly still see the exception; assert on
  `StoreError`, not a traceback string.
- **The login cookie is `"<issued>.<hmac>"`.** `_cookie_is_valid` rejects a
  tampered or expired value; `_cookie_value` needs the issue time, and the
  docstring must not claim the cookie is harmless — it is a bearer credential
  for its lifetime.
- **Web tests send `Host: testserver`.** It is in `LOOPBACK_HOSTS`; a new
  non-loopback test must set `settings.allow_remote_host = True`.

## Testing rules

- Patching `SOURCES` must target where it is *used*:
  `coldtrail.pivot.SOURCES`, `coldtrail.harvest.SOURCES`,
  `coldtrail.cli.collect.SOURCES`, `coldtrail.cli.osint.SOURCES`.
- Web tests seed a real SQLite file in `tmp_path` and build with
  `create_app(settings)`; never the default DB path.
- Async web jobs: poll `/api/jobs/{id}` until `done`/`error`
  (`_wait_job` in `tests/test_web.py`).
- Every bug fix gets a regression test. The 2026-10-30 audit tests live in
  `tests/test_audit_fixes.py`; the 2026-10-31 pass in
  `tests/test_audit_2026_10_31.py`; 0.10 features in `tests/test_features_v10.py`.
- `tests/conftest.py` blocks real sockets for every test. A test that needs one
  must be marked `@pytest.mark.network`, and that marker needs a reason.
- Source tests: `tests/test_sources.py`, `test_new_sources.py`,
  `test_sources_expanded.py`; engine: `test_engine_upgrades.py`; workflows:
  `test_workflows.py`; contracts: `test_contracts.py`; evidence:
  `test_evidence.py`; integrations: `test_integrations.py`; case dossiers:
  `test_casework.py`; live-investigation regressions:
  `test_investigation_regressions.py`, `test_twitch_regression.py`.
- `tests/test_docs_drift.py` guards README/AGENTS counts and documented routes.
  Update it when adding a command, schema version, or route.
- `tests/test_media_manifest.py` fails when `docs/assets` or the UI files they
  show drift. Regenerate with `scripts/capture_media.py`, never by hand-editing
  an image.

## Definition of done

- [ ] `uv run pytest` passes (no network).
- [ ] `uv run ruff check .` and `uv run ruff format --check .` pass.
- [ ] `uv run mypy` passes.
- [ ] `uv run coldtrail doctor --offline` exits cleanly.
- [ ] New behavior has a regression test named in the commit/PR.
- [ ] `AUDIT.md` (or the current dated audit) is updated when fixing a finding.
- [ ] README claims match the code; no hardcoded test counts.
- [ ] No secrets, DBs, exports, or generated artifacts in the diff.

## What not to touch

- `LICENSE`, `CITATION.cff`, and the security policy text.
- Formatting of unrelated files; do not reformat the whole tree in a fix PR.
- Generated output: `dist/`, `.coverage`, caches, `tests/fixtures/contracts/_record.db*`.
- Existing commit trailers or the historical `slopmanufacturer` login.
- Public APIs without a deprecation path (`Store`, `coldtrail.cli:app`/`main`,
  `persist_pivot`, the JSON API shapes, and the schema `--json` contracts).

## Web API surface

Pages: `/`, `/runs`, `/runs/{id}`, `/runs/{id}/export?format=…`, `/search`
(`scope=posts|profiles|entities|all`, `prefix`, `source`, `username`),
`/sources`, `/cases`, `/tools`, `/pivot`, `/jobs/{id}`, `/diff`
(`format=page|html`), `/help`, `/login`, `/logout`, `/evidence/{id}`,
`/healthz`, `/api/docs`, `/api/openapi.json`.

JSON: `/api/health`, `/api/stats`, `/api/runs`, `/api/runs/{id}`,
`/api/runs/{id}/graph`, `/api/diff?a=&b=`,
`/api/search?q=&scope=&prefix=&source=&username=`, `/api/sources` (includes
`health`), `/api/jobs/{id}`, `/api/jobs/{id}/stream` (SSE), `POST /api/pivot`,
`/api/evidence/{id}`.

Auth (when `web_token` is set): bearer / `X-API-Key` / cookie; `/login` sets an
HMAC-derived cookie (`SameSite=Strict`, `HttpOnly`, `Secure` over HTTPS).
`/healthz`, `/api/health`, `/login`, `/logout`, and `/static` stay public.

Export formats: `json`, `jsonl`, `csv` (`&table=`), `graphml`, `gexf`, `dot`,
`html`, `md`, `stix`, `sarif`, `maltego`; `&redact=true` for redacted payloads.
`--json` payload contracts live in `coldtrail/schemas.py` and are emitted by
`coldtrail schema <name>`.

## Further reading

- `README.md` — user-facing overview, proof media, limits.
- `CONTRIBUTING.md` — setup, adding a source, privacy invariants, release.
- `SECURITY.md` — threat model, reporting, accepted limitations.
- `AUDIT.md` — the 2026-10-30 audit record with tests and accepted risks.
- `CHANGELOG.md` — user-visible changes.
