# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.8.x   | yes       |
| < 0.8   | no        |

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
token exposes the database, evidence store, and external-tool runner to the
network. Do not do that.

When exposed behind a reverse proxy:

- set `--token` (or `COLDTRAIL_WEB_TOKEN`),
- set `COLDTRAIL_TRUST_PROXY=1` so rate limiting keys on `X-Forwarded-For`,
- terminate TLS at the proxy and forward `X-Forwarded-Proto`,
- keep the job store single-process (in-memory jobs are not shared across
  `uvicorn --workers`).

## Built-in controls

- External tools run as argument vectors (`shell=False`) with option-injection
  validation on the target.
- Uploads are read in bounded chunks (50 MB limit).
- Pivots and tool runs are rate-limited per client; `/login` has its own
  stricter window.
- Harvested URLs are rendered through an `http`/`https` allowlist and HTML
  reports escape untrusted content.
- Breach lookups are metadata-only; Pwned Passwords uses k-anonymity and never
  sends or logs the password or full hash.
- Evidence blobs are content-addressed (SHA-256) and verified on demand.
