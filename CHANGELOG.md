# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.10.3] - 2026-10-31

### Fixed

- Pinned HTTP and TLS connections prefer an IPv4 address when a dual-stack host
  publishes one, so `domain`, `ip`, and `ct` no longer time out on IPv4-only
  networks.

## [0.10.2] - 2026-10-31

### Fixed

- Web UI: requests with a non-loopback `Host` header are refused, and non-GET
  requests with a foreign `Origin` or a cross-site `Sec-Fetch-Site` are `403`.
  Loopback binding is not a security boundary — DNS rebinding and drive-by form
  posts reached every page and API route before this.
- The TLS probe (`domain --deep`) resolves once and connects to the validated
  address, and is skipped under `--proxy`/`--tor` instead of opening a direct
  socket that bypassed the proxy.
- Direct HTTP connections are pinned to the validated address
  (`_PinnedTransport`), closing the check-then-resolve window; the redirect
  check now resolves DNS when the host changes.
- The test suite no longer opens a real connection: `tests/conftest.py` blocks
  `socket.connect`, and `test_lookup_domain_deep` patches the TLS probe.
- CSV and Maltego exports neutralize spreadsheet formulas (`=`, `+`, `-`, `@`)
  from harvested text.
- A malformed `COLDTRAIL_*` value or config file is a one-line `ConfigError`
  (exit 2), not a traceback; unknown keys and `[section]` tables are rejected.
- A corrupt or unopenable database raises `StoreError` and exits 2, including
  from `doctor`; `coldtrail.cli:main` is the new console entry point.
- A malformed proxy URL no longer crashes `config`/`doctor`
  (`redact_url_credentials` degrades to `[invalid url]`).
- `Retry-After` above 10s is treated as a refusal instead of sleeping; one
  source could stall a pivot for hours.
- CT subdomains, MX providers, and takeover CNAMEs require a label boundary, so
  `notexample.com` is no longer a subdomain of `example.com`.
- `write_private` creates exports with mode 0600 via `os.open` instead of
  chmod-after-write, which left a 0644 window and silently kept 0644 when chmod
  failed.
- `infer_timezone` bins posting hours in UTC, so the same instants infer the same
  offset regardless of how the source formatted the timestamp.
- A corrupt `audit.args_json` row no longer crashes `coldtrail audit`.
- `timeline --since <non-ISO>` and `export --table <unknown>` fail with exit 2
  instead of returning an empty result.
- Evidence: `add_evidence(source_path=...)` streams the file instead of reading
  it into RAM, and `verify_evidence` pages through attachments.
- Pwned Passwords keeps the 5-character hash prefix out of the local cache/raw
  key and out of error details; the request still sends only the prefix.

### Changed

- Dependency refresh: `textual` 8.2.8, `rich` 15.0.0, `fastapi` 0.162.0,
  `pytest-asyncio` 1.4.1, `ruff` 0.17.3; GitHub Actions `checkout` v7,
  `configure-pages` v6, `deploy-pages` v5, `upload-pages-artifact` v5, and
  `codeql-action` v4.
- Tests use Starlette's supported `httpx2` test client (dev-only), so the suite
  no longer emits the `httpx` deprecation warning.
- `SECURITY.md`, `README.md`, and `AGENTS.md` now describe the pinned-transport
  behavior and the `COLDTRAIL_ALLOW_REMOTE_HOST=1` requirement behind a reverse
  proxy.
- TUI tests now read `Static` text on both Textual 2.x and 8.x via a
  `_static_text()` helper.
- The login cookie is `"<issued>.<hmac>"` and expires server-side; it is still a
  bearer credential for its lifetime, and the docstring now says so.

## [0.10.1] - 2026-10-30

### Fixed

- CodeQL `py/overly-large-range`: the XML character filter is now an explicit
  XML 1.0 codepoint check instead of an overlapping regex range. Behavior is
  unchanged (controls, surrogates, and noncharacters are stripped before
  escaping).

### Changed

- Removed the superseded `terminal-demo.gif` and `web-pivot.png` assets; the
  generated media is `cli-pivot.gif`, `web-pivot.gif`, and the page screenshots.
- Regenerated the README proof media for 0.10.1.

### Security

- Dismissed the two CodeQL `py/weak-sensitive-data-hashing` alerts as documented
  false positives: SHA-1 is required by the Pwned Passwords k-anonymity protocol
  and only the five-character prefix leaves the machine (`AUDIT.md`).

## [0.10.0] - 2026-10-30

### Added

- **`coldtrail config`.** Shows every effective setting, where it came from
  (default / TOML / environment / flag), and redacts secrets. `--json` is a
  stable contract (`coldtrail schema config`).
- **`coldtrail schema`.** Emits JSON Schema (draft 2020-12) for the `pivot`,
  `run`, `diff`, `sources`, `doctor`, `config`, and `stats` payloads so
  downstream tooling can validate `--json` output.
- **SARIF 2.1.0 export.** `coldtrail export <run> --format sarif` (and
  `?format=sarif` on the web export routes) turns profiles, entities, and
  clusters into SARIF results for CI/code-scanning pipelines.
- **HTML run diff.** `coldtrail diff A B --format html [-o file]` and
  `/diff?a=&b=&format=html` render a self-contained diff dossier.
- **Source health.** `coldtrail source health [--live]` records per-source
  status, detail, and latency in a new `source_health` table (schema v7).
  `/sources` and `/api/sources` surface the recorded health.
- **Search scopes and snippets.** `coldtrail search --scope
  posts|profiles|entities|all`, `--prefix`, `--source`, and `--username`.
  Post results include an FTS5 snippet; the web search page and `/api/search`
  accept the same parameters.
- **Batch concurrency.** `coldtrail batch -j/--jobs N` pivots targets
  concurrently with one shared `Fetcher`, so pacing, budget, and circuit state
  span the whole batch.
- **CI gates.** Coverage floor (73%), mypy over core/store, Python 3.14 in the
  matrix, wheel install smoke test, Bandit, pip-audit, CodeQL, and Dependabot.
- **More contract fixtures.** 19 additional curated sources now have recorded
  fixtures (30 total), and a test replays every committed fixture offline.

### Changed

- Split the web app factory into `web/helpers.py`, `web/api_routes.py`, and
  `web/case_routes.py`; `create_app()` remains the public composition root.
- The SQLite database and its parent directory are created under `umask(0o077)`
  so the file is owner-only from its first byte, not after a chmod.
- Removed the stale `GOOD_FIRST_ISSUES.md` and `LAUNCH.md` scaffolding; release
  guidance now lives in `CONTRIBUTING.md`, and the audit record in `AUDIT.md`.
- Timeline queries now order and paginate in SQL using a normalized
  `posts.created_ts` epoch column (schema v6). `--limit` returns the newest
  window in chronological order; `--since/--until` no longer load every post.
- Container base images are pinned by digest.
- Raised Pillow to 13.x, cryptography to 50.x, certifi, and pytest 9.x to clear
  known CVEs.

### Fixed

- Timelines no longer sort ISO timestamps with different UTC offsets
  lexicographically.
- Search filters (`source:`, `username:`) and prefix matching now work, and
  profile/entity scopes are searchable.
- HTML and Markdown dossiers, `harvest` tombstones, and `watch` windows now use
  the same chronological ordering as `Store.timeline()`.
- GraphML/GEXF exports are well-formed XML for handles or display names that
  contain quotes or control characters.
- A cached WAF/challenge page is no longer replayed as a valid profile; blocked
  responses are classified before they are cached and re-checked on cache hits.
- The HTTP cache varies by `Accept` and decodes cached bodies with their stored
  charset, so JSON/HTML requests cannot poison each other.
- Evidence is hashed from the bytes actually read, and evidence blob paths
  reject non-SHA-256 digests.
- `doctor` and the audit log redact proxy credentials; `doctor` warns when the
  config file is group/world-readable.
- Redirects to loopback/link-local hosts are blocked unless private targets are
  explicitly allowed.
- Matrix IDs (`@user:server`) are no longer misclassified as Telegram handles.
- Blank/whitespace targets are rejected by pivot, harvest, graph, and the web
  routes; case names reject whitespace.
- A corrupt SQLite database or corrupt JSON row no longer crashes commands with
  a traceback.
- Markdown tables escape `|` and newlines; DOT exports default a missing score
  to `0`.
- README/AGENTS counts no longer drift (tests are no longer hardcoded; the
  command count is 48 top-level / 61 leaf).

## [0.9.0] - 2026-10-27

### Privacy

- **Raw HTTP bodies are now opt-in.** `keep_raw` defaults to `False`; use
  `--raw` for replay/contract fixtures. Recording forces raw capture only for
  the fixture workflow. `--raw/--no-raw` is tri-state, so config/env values
  are preserved when the flag is omitted.
- **Avatar hashing is opt-in.** `--avatar-hash` (or
  `COLDTRAIL_AVATAR_HASH=1`) downloads third-party profile images.
- **Owner-only storage.** The SQLite DB, WAL/SHM sidecars, and evidence blobs
  are created `0600`; evidence directories are `0700`.
- **Owner-only exports.** CLI exports, dossiers, case exports, decrypted files,
  and evidence copies are written `0600`.
- **Tor no longer leaks DNS.** `--tor` uses `socks5h://127.0.0.1:9050`.
- **Sensitive identifiers stay out of cache/raw keys.** Email targets are
  SHA-256 hashed; Shodan/Hunter API keys are no longer persisted in cache keys.
  Hunter now authenticates with `X-API-Key`.
- **Auth cookies are HMAC-derived**, not the raw bearer token. Added
  `/logout`, HSTS on HTTPS, and `Permissions-Policy`/`base-uri`/`form-action`
  CSP hardening.
- **Non-loopback binds fail closed** without `--token`; use
  `--allow-unauthenticated` only as an explicit override.
- **Audit log redacts secrets** from `--token`, `--passphrase`, `--api-key`,
  and similar flags.
- **Privacy headers:** `img-src 'self' data:`, `Permissions-Policy`,
  `Cache-Control: no-store`, and existing `no-referrer`.
- **Retention covers evidence and audit rows.** `prune` removes orphan evidence
  blobs and old audit entries; `--retention-days` and web/TUI startup apply it.
- **Doctor privacy posture:** `doctor --offline --json` reports telemetry, raw
  retention, cache TTL, retention, proxy/Tor, token, DB mode, and config mode.
- README and the Pages site now document the privacy model and its limits.

### Security

- Parse untrusted XML with `defusedxml` (nmap, Medium RSS, Steam).
- Replace a production `assert` in evidence loading with a real error.
- Cap stored/parsed HTTP bodies at 2 MB.
- Sanitize corpus headers with control characters/trailing whitespace.
- Sanitize user-controlled case names in `Content-Disposition`.

### Fixed

- Accept comma-separated source lists (`-s github,reddit`).
- Quote email values in PGP and EmailRep profile URLs.
- Bound web job event memory and prune retention on web/TUI startup.

## [0.8.0] - 2026-10-27

### Changed

- **Renamed the project to ColdTrail.** The distribution and import package are
  now `coldtrail`, the CLI is `coldtrail`, environment variables use the
  `COLDTRAIL_*` prefix, default config/data paths are
  `~/.config/coldtrail` and `~/.local/share/coldtrail`, the login cookie is
  `coldtrail_token`, and the Docker user/image, systemd units, docs, and
  GitHub Pages URLs were updated.
- Existing databases are not moved automatically. Point `--db` at the old file
  or move it to `~/.local/share/coldtrail/coldtrail.db`.

## [0.7.0] - 2026-10-27

### Added

- **Username/email coverage:** external wrappers for `maigret`, `naminter`
  (WhatsMyName dataset), `social-analyzer`, `blackbird`, plus native Threads,
  Pinterest, Tumblr, VK, Snapchat, Instagram, X (bearer token), and Hunter.io
  (API key) sources.
- **Social/media coverage:** `instaloader` (Instagram profile + post JSON) and
  `twscrape` (X/Twitter profile lookup) integrations.
- **GitHub Pages documentation site** under `docs/` with `robots.txt`,
  `sitemap.xml`, Open Graph/Twitter metadata, and JSON-LD structured data.
- **CI matrix** for Python 3.11–3.13, `LICENSE`, `SECURITY.md`, `CITATION.cff`,
  and this changelog.
- Regression tests for every fix below and for all new sources/wrappers.

### Security

- Reject external-tool targets that start with `-` or contain NUL/newlines,
  closing an option-injection path in `run_tool` and `POST /tools/external`.
- Stream uploads in 1 MiB chunks and enforce the 50 MB cap before buffering.
- Bound the web rate-limit table and rate-limit `/login` against token guessing.
- Add `Secure` to the login cookie when served over HTTPS.
- Stop exposing the database path from the public `/healthz` endpoint.

### Fixed

- Pivot jobs no longer stay `running` forever when the database cannot be
  opened; `finished_at` is always set and the error is reported.
- SSE streams send `no-cache`/`X-Accel-Buffering: no` headers, heartbeats, and
  a terminal timeout instead of hanging behind a buffering proxy.
- Profile identity is case-insensitive (schema v5, with a deduplicating
  migration), matching every `COLLATE NOCASE` query and fixing duplicate
  `Alice`/`alice` rows and history/diff inconsistencies.
- `robots.txt` is fetched over the URL's own scheme and HTML soft-404s are
  ignored instead of being parsed as rules.
- Invalid JSON from an API now raises `FetchError` instead of silently becoming
  `not_found`.
- Entity migration detects the old unique index via `PRAGMA index_xinfo` rather
  than string-matching `sqlite_master` SQL.
- Profile history uses one batched query instead of N+1 per profile.
- Username expansion deduplicates in O(n) instead of O(n²).
- Long-running watches bound their alert de-duplication memory.

### Changed

- Version bumped to 0.7.0; README rewritten for a fast first read.

## [0.6.0] - 2026-10-19

- External tool registry, importers, content-addressed evidence, case dossiers,
  grouped help, and the interactive menu.

## [0.5.2] - 2026-10-19

- Speed and usability: bounded probes, HTML cache caps, readable pivot output.

## [0.5.1] - 2026-10-19

- Live-investigation hardening: false-positive fixes across Twitch, Bluesky,
  declarative pages, and expansion.

## [0.5.0] - 2026-10-19

- Cryptographic identity, deep infrastructure recon, contracts, diff, deploy.
