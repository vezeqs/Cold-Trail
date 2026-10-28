# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.9.x   | yes       |
| < 0.9   | no        |

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability.

Use GitHub's private vulnerability reporting on the repository
(`Security` → `Report a vulnerability`), or email the maintainer listed in the
repository profile. Include:

- affected version and interface (CLI, TUI, web),
- a minimal reproduction,
- impact (data exposure, RCE, SSRF, auth bypass, …).

You can expect an acknowledgement within 72 hours and a coordinated fix. Please
give us a reasonable window before public disclosure.

## Threat model

`ColdTrail` is a **local-first** OSINT tool. The default `serve` bind is
`127.0.0.1`; the web UI has no authentication unless `--token` /
`COLDTRAIL_WEB_TOKEN` is set. Binding to a non-loopback address without a
token is **refused**; `--allow-unauthenticated` is an explicit, discouraged
override. Do not expose the UI without a token.

When exposed behind a reverse proxy:

- set `--token` (or `COLDTRAIL_WEB_TOKEN`),
- set `COLDTRAIL_TRUST_PROXY=1` so rate limiting keys on `X-Forwarded-For`,
- terminate TLS at the proxy and forward `X-Forwarded-Proto`,
- keep the job store single-process (in-memory jobs are not shared across
  `uvicorn --workers`).

The tools workbench can query arbitrary domains/IPs (including internal ones),
run local external binaries, and fetch URLs. Treat it as an operator console:
do not expose it to untrusted users, even with a token.

## Privacy design

ColdTrail is privacy-first by default:

- **No telemetry.** No analytics, crash reporting, update checks, or hidden
  network calls. `doctor --offline` skips the only optional reachability probe.
- **Local data only.** SQLite, WAL/SHM, and evidence blobs are created with
  `0600`; evidence directories use `0700`. There is no cloud component.
- **Raw HTTP bodies are off by default.** `--raw` opts in for replay and
  contract recording. The local HTTP cache can be disabled with `--no-cache`.
- **Avatar hashing is off by default.** `--avatar-hash` (or
  `COLDTRAIL_AVATAR_HASH=1`) downloads profile images from source platforms.
- **Sensitive identifiers are not indexed in URLs.** Email targets are hashed
  in cache/raw keys; API keys are never written there. HIBP, EmailRep, and
  Hunter use auth headers; Shodan's key travels over TLS and is redacted
  locally.
- **Tor uses remote DNS.** `--tor` sets `socks5h://127.0.0.1:9050`, preventing
  local DNS leaks. `--proxy` accepts HTTP/SOCKS proxies.
- **Web privacy headers.** The UI sends CSP, `Referrer-Policy: no-referrer`,
  `Permissions-Policy`, and `Cache-Control: no-store`; there are no
  third-party assets. Auth cookies are HMAC-derived, not the bearer token.
- **Retention.** `--retention-days N` or `prune --days N` removes old runs,
  raw/cache rows, audit entries, and orphan evidence blobs.
- **Breach privacy.** Breach features are metadata-only; Pwned Passwords uses
  k-anonymity and never sends or logs the password or full hash.

**Limits.** Every source you probe receives the target identifier — that is
inherent to OSINT. The database is not encrypted at rest by default; use
full-disk encryption on shared hosts. `--raw` and the HTTP cache may retain
third-party content, so prune them.

## Built-in controls

- External tools run as argument vectors (`shell=False`) with option-injection
  validation on the target.
- Uploads are read in bounded chunks (50 MB limit); HTTP bodies are capped at
  2 MB before storage/parsing.
- Pivots and tool runs are rate-limited per client; `/login` has its own
  stricter window.
- Harvested URLs are rendered through an `http`/`https` allowlist and HTML
  reports escape untrusted content.
- XML from third-party sources is parsed with `defusedxml` to block entity
  expansion.
- Breach lookups are metadata-only; Pwned Passwords uses k-anonymity and never
  sends or logs the password or full hash.
- Evidence blobs are content-addressed (SHA-256) and verified on demand.
