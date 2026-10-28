# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

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
