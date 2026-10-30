# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

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

### Changed

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
