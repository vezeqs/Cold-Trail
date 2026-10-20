# larpharvester

OSINT CLI for **pivoting** usernames and emails across public sources, **harvesting** profiles and
posts into a local SQLite database, **correlating** them into inferred identities, and **reporting**
the result as JSON, CSV, GraphML, GEXF, DOT, or a self-contained HTML dossier.

Three interfaces over one database:

- **CLI** — 42 commands, scriptable, JSON/JSONL output
- **TUI** — six-tab terminal console with row drill-down (`p` pivot, `h` harvest, `d` diff)
- **Web UI** — local FastAPI app with a JSON API, live SSE pivot streaming, an interactive
  identity graph, an OSINT workbench, run diffing, case dossiers, optional auth, and export downloads

495 sources out of the box: 42 hand-written API sources plus 453 declarative definitions generated
from the [Sherlock](https://github.com/sherlock-project/sherlock) dataset (MIT). No API keys needed
for most of it; optional keys unlock GitHub rate limits, HIBP, and EmailRep.

v0.5.0 adds cryptographic identity collection (SSH/GPG keys, Gists, Bluesky DID history, Nostr
NIP-05, ENS), avatar EXIF/GPS metadata, live TLS certificate inspection, BGP/ASN enrichment,
certificate-transparency search, Wayback profile recovery, run-to-run diffing, source contract
testing with recorded fixtures, and Docker/systemd deployment.

## Install

```bash
uv sync
uv run larpharvester --help
```

## Interfaces

```bash
# Terminal UI: dashboard, pivot runner, browse stored runs, full-text search
uv run larpharvester tui

# Local web UI on http://127.0.0.1:8765 (JSON API + docs at /api/docs)
uv run larpharvester serve
uv run larpharvester serve --port 9000 --open
```

The web UI runs pivots as background jobs with **live Server-Sent Events streaming** (each source
appears the moment it finishes), renders an **interactive force-directed identity graph** per run
(drag, zoom, click to inspect), and ships an **OSINT workbench** for domain/IP/phone/dorks/archive/
breach/harvest/follow-graph/re-clustering. Case, tag, and note management is available in both the
web UI and TUI. The TUI streams pivot rows live into its results table. Both respect the same
`--db` / config as the CLI.

## Quickstart

```bash
# Username pivot across the curated sources, with correlation + clusters
uv run larpharvester pivot alice

# Add the 478-site web corpus
uv run larpharvester pivot alice --web

# Probe generated handle variants too (_official, leet, dotted, ...)
uv run larpharvester pivot alice --variants

# Email pivot, then follow linked handles from Gravatar/Keybase/EmailRep
uv run larpharvester pivot alice@example.com --expand

# Multi-hop expansion: email -> username -> email -> ...
uv run larpharvester pivot alice@example.com --expand --depth 2

# Batch pivots from arguments or a newline-delimited file
uv run larpharvester batch alice bob carol -s social
uv run larpharvester batch -f targets.txt --json

# Re-correlate stored profiles with the current engine (single run or cross-run)
uv run larpharvester recluster --run 3
uv run larpharvester recluster --threshold 0.6

# Harvest posts (paginated), then only new ones next time
uv run larpharvester harvest alice -s reddit -n 200
uv run larpharvester harvest alice -s reddit --incremental

# Follow graph (Bluesky, Mastodon, GitHub)
uv run larpharvester graph alice -s bluesky

# Continuous monitoring with alerts
uv run larpharvester watch alice -s reddit -s hackernews --interval 3600 \
    --alert ntfy --alert-target my-osint-topic
```

## Query and report

```bash
uv run larpharvester runs
uv run larpharvester profiles --run 3
uv run larpharvester posts --username alice --since 2024-01-01
uv run larpharvester search "crypto wallet"          # FTS5 over post text
uv run larpharvester entities --kind eth
uv run larpharvester clusters --run 3
uv run larpharvester edges --actor alice              # stored follow graph rows
uv run larpharvester timeline --run 3
uv run larpharvester history --username alice         # bio/avatar changes across runs
uv run larpharvester analyze --run 3                  # timezone + writing-style similarity

uv run larpharvester export 3 --format graphml -o graph.graphml
uv run larpharvester export 3 --format html -o dossier.html
uv run larpharvester export 3 --format md -o dossier.md          # Markdown report
uv run larpharvester export 3 --format stix -o bundle.json       # STIX 2.1 bundle
uv run larpharvester export 3 --format maltego -o edges.csv      # Maltego import
uv run larpharvester report 3 -o dossier.html
uv run larpharvester export 3 --redact -o safe.json
uv run larpharvester export 3 --encrypt -o run3.bin   # passphrase in LARPHARVESTER_PASSPHRASE
uv run larpharvester decrypt run3.bin run3.json
```

## Intel helpers

```bash
uv run larpharvester dorks alice                     # 52 search-engine dork URLs
uv run larpharvester dorks alice --image https://cdn.example/a.png
uv run larpharvester domain example.com              # RDAP + DNS + crt.sh subdomains
uv run larpharvester domain example.com --deep       # + DMARC, security.txt, favicon MMH3, takeovers
uv run larpharvester phone "+351 912 345 678"        # carrier, region, timezone
uv run larpharvester ip 8.8.8.8                       # PTR, reverse IP, Shodan (optional key)
uv run larpharvester ip 8.8.8.8 --asn                 # + RIPE ASN/prefix and IP RDAP
uv run larpharvester archive https://example.com/    # Wayback CDX captures
uv run larpharvester archive https://example.com/ --snapshot 20200101000000
```

## Sources

| Group | Sources |
| --- | --- |
| `social` | reddit, hackernews, mastodon, bluesky, telegram, youtube, twitch, steam, chesscom, lichess, roblox, duolingo, tiktok, medium, substack, linktree, matrix, nostr, ens |
| `dev` | github, gitlab, codeberg, stackoverflow, kaggle, huggingface, npm, pypi, devto, hackerone, crates, dockerhub, rubygems, packagist |
| `email` | gravatar, keybase, pgp, github-commits, hibp, emailrep, hudsonrock, leakcheck, libravatar |
| `web` | 453 declarative sites (Sherlock corpus), selectable with `--web` or `-g web` |

```bash
uv run larpharvester sources                 # curated only
uv run larpharvester sources --all           # include the web corpus
uv run larpharvester sources -g email
uv run larpharvester source test github torvalds
```

Declarative sites support `status_code`, `message`, and `response_url` checks, per-site regexes,
custom headers, and probe URLs. Regenerate the corpus with `python scripts/build_sites.py --fetch`
— it pins a Sherlock git ref and stamps the provenance + sha256 into the file header.

## Correlation model

Every pair of found profiles is scored; pairs above `0.5` become edges, and union-find turns edges
into **clusters** (inferred identities, confidence = weakest edge):

| Signal | Weight |
| --- | --- |
| Same avatar URL (known default avatars ignored) | 0.9 |
| Perceptual avatar hash match (dHash, Hamming ≤ 8) | 0.85 |
| Identical bio with ≥3 distinctive tokens | 0.7 |
| Same website (generic roots ignored) | 0.6 |
| ≥70% distinctive-token bio overlap | 0.5 |
| Handle mentioned in the other bio | 0.5 |
| Shared extracted entity (email, crypto, phone, chat handle, onion) | 0.8 |
| Identical cryptographic identifier (SSH/GPG key, Bluesky DID, Nostr pubkey, ENS/chain address) | 0.95 |
| Same camera serial / capture time+model in avatar EXIF | 0.4 |
| Same author tag in avatar EXIF | 0.3 |
| Handle differs only by separators (`alice_sec` ~ `alicesec`) | 0.2 |
| Handle Jaro-Winkler similarity ≥ 0.92 | 0.15 |
| Same display name | 0.3 |
| Accounts created within 7 days | 0.1 |
| Same inferred timezone | 0.1 |
| Same language | 0.05 |
| Timezone difference ≥ 4h | −0.1 |
| Language mismatch | −0.05 |

Coverage is reported explicitly (`found / not_found / blocked / error`), so a bot wall never looks
like an absence. Reports also show a calibrated **confidence** alongside the additive evidence
score (logistic mapping, capped at 0.99); stored scores stay additive for interpretability.

## Cryptographic keys, decentralized identity & metadata

- **SSH / GPG keys** — GitHub, GitLab, and Codeberg key endpoints are collected during checks;
  OpenSSH `SHA256:` fingerprints are computed locally and GPG UID emails are extracted. An exact
  key match between two accounts is treated as near-proof (0.95).
- **Gists** — GitHub public gists are harvested as posts alongside events.
- **Bluesky DID history** — `did:plc:` accounts are resolved through the PLC audit log for
  historical handles and the PDS host.
- **Mastodon WebFinger** — `user@custom-domain` handles resolve to the real ActivityPub host.
- **Nostr NIP-05** — `name@domain` (or `_@domain`) resolves to a hex pubkey and relays.
- **ENS** — `.eth` names resolve to Ethereum addresses via public ENS metadata.
- **Avatar EXIF** — camera make/model, serial, software, author, capture timestamps, and GPS
  coordinates are extracted from downloaded avatars and fed into entity extraction/correlation.
- **Wayback recovery** — `archive <url> --recover` rebuilds historical titles/descriptions from
  archived captures (deleted bios, renamed accounts).

## Infrastructure recon

- `domain --deep` adds SPF/DMARC, security.txt, favicon MurmurHash3 (Shodan-compatible),
  subdomain-takeover fingerprints, and a **live TLS handshake** (issuer, validity, SANs, TLS version).
- `ip --asn` adds RIPE Stat ASN/prefix data and IP RDAP; BGP announced prefixes and the AS holder
  are displayed.
- `ct <query>` searches certificate-transparency logs for an identity string.

## Run diffing & source contracts

```bash
uv run larpharvester diff 3 4                      # added/removed/changed profiles, entities, links, posts
uv run larpharvester source verify -s github       # replay recorded fixtures offline
uv run larpharvester source verify --record -s github   # capture fresh fixtures from live APIs
uv run larpharvester source verify --live -s github     # probe live and validate the contract
```

Recorded fixtures live in `tests/fixtures/contracts/`; replaying them through the parsers catches
upstream API drift and parser regressions without touching the network.

## Storage

SQLite, schema v3, auto-migrated. Tables: `runs`, `checks`, `profiles`, `posts`, `links`,
`clusters`, `cluster_members`, `entities`, `edges`, `profile_history`, `cursors`, `http_cache`,
`raw`, `probe_cache`, `audit`, `cases`, `case_runs`, `tags`, `notes`, plus `posts_fts` (FTS5).

```bash
uv run larpharvester db
uv run larpharvester prune --days 30 --vacuum
uv run larpharvester case new op-x && uv run larpharvester case add op-x 3
uv run larpharvester tag profile github:alice suspect
uv run larpharvester note profile github:alice "check the avatar"
uv run larpharvester audit
```

## Breach exposure auditing

Defensive checks against industry-standard breach APIs — these answer "was this
exposed?", never "what is it?":

```bash
# Which breaches does an email appear in? (needs HIBP_API_KEY)
uv run larpharvester breach alice@example.com
uv run larpharvester breach alice@example.com --json

# Multi-provider exposure audit: HIBP + HudsonRock Cavalier + LeakCheck public
uv run larpharvester breach alice@example.com --all

# Is a password in the Pwned Passwords corpus? (no key needed)
uv run larpharvester pwned                          # hidden prompt
uv run larpharvester pwned --password-env MY_PW     # scripting
```

`pwned` uses SHA-1 k-anonymity: only the first five hex characters of the hash
are transmitted, so neither the password nor the full hash ever leaves the
machine. Exit code is `1` when exposed, `0` when clean — safe for CI/scripts.

## Operational features

- **Politeness:** per-host rate limit (`requests_per_second`), jitter, circuit breaker after 5
  failures, ETag revalidation, HTTP cache, negative probe cache, optional `--respect-robots`.
- **OPSEC:** `--proxy`, `--tor`, configurable User-Agent, `--max-requests` budget.
- **Reproducibility:** raw responses are retained by default; `--replay` serves them offline.
- **Monitoring:** `watch` diffs new posts, marks deleted posts as tombstones, records profile field
  changes, and dispatches webhook/Discord/ntfy/SMTP alerts.
- **Audit:** every command is logged with its argv.
- **Retention:** `retention_days` prunes automatically at startup; `prune` does it manually.
- **Plugins:** third-party sources via the `larpharvester.sources` entry-point group.

## Web API

`larpharvester serve` exposes a JSON API alongside the HTML pages (interactive docs at
`/api/docs`):

| Endpoint | Purpose |
| --- | --- |
| `GET /healthz`, `/api/health` | Liveness + DB check (503 when the DB is unusable) |
| `GET /api/stats` | Table counts, DB info, source health |
| `GET /api/runs`, `/api/runs/{id}` | Run listing and full run export |
| `GET /api/runs/{id}/graph` | Nodes + edges for the interactive identity graph |
| `GET /api/diff?a=&b=` | Added/removed/changed profiles, entities, links, clusters, posts |
| `GET /api/search?q=` | FTS5 post search |
| `GET /api/sources` | Source registry |
| `POST /api/pivot` | Queue a pivot (`{"target": "...", "include_web": false, "depth": 1, ...}`) → `202 {job_id}` |
| `GET /api/jobs/{id}` | Job status, counts, and the full event list |
| `GET /api/jobs/{id}/stream` | Server-Sent Events: `check` per source, then `done` |

Run exports are downloadable at `/runs/{id}/export?format=json|jsonl|csv|graphml|gexf|dot|html|md|stix|maltego`
with optional `&redact=true` and `&table=` for CSV. Case pages (`/cases/{name}`) aggregate every
run in the case and export a merged dossier at `/cases/{name}/export?format=…`. Responses carry a
strict CSP (`script-src 'self'`), `X-Frame-Options: DENY`, and harvested URLs are scheme-checked
before becoming links. The web workbench at `/tools` runs domain, IP, phone, dorks, archive, breach,
Pwned Passwords, harvest, follow-graph, and re-clustering jobs; `/cases` supports creating cases,
attaching runs, and adding tags/notes; `/diff` compares any two runs; every profile/entity row has a
one-click **Pivot →** action.

**Optional auth:** set `LARPHARVESTER_WEB_TOKEN` (or `larpharvester serve --token …`) to require a
bearer token (`Authorization: Bearer …` / `X-API-Key`), or sign in at `/login` to receive an
HTTP-only cookie. `/healthz` stays public for container probes. Expensive endpoints are rate
limited per client (20 requests/minute).

## Configuration

`~/.config/larpharvester/config.toml` (or `--config`), with env overrides:

| Key / env | Default | Meaning |
| --- | --- | --- |
| `db_path` / `LARPHARVESTER_DB` | `$XDG_DATA_HOME/larpharvester/larpharvester.db` | SQLite path |
| `timeout` / `LARPHARVESTER_TIMEOUT` | `10` | Request timeout |
| `concurrency` / `LARPHARVESTER_CONCURRENCY` | `8` | In-flight requests |
| `requests_per_second` / `LARPHARVESTER_RPS` | `5` | Per-host pacing |
| `proxy` / `LARPHARVESTER_PROXY` | unset | HTTP/SOCKS proxy |
| `tor` / `LARPHARVESTER_TOR` | `false` | Use `socks5://127.0.0.1:9050` |
| `cache_ttl` / `LARPHARVESTER_CACHE_TTL` | `86400` | HTTP cache TTL |
| `negative_cache_ttl` | `86400` | Probe cache TTL |
| `max_requests` / `LARPHARVESTER_MAX_REQUESTS` | `0` | Per-run budget (0 = unlimited) |
| `keep_raw` / `LARPHARVESTER_KEEP_RAW` | `true` | Retain raw bodies |
| `retention_days` / `LARPHARVESTER_RETENTION_DAYS` | `0` | Auto-prune age |
| `respect_robots` | `false` | Honour robots.txt |
| `web_token` / `LARPHARVESTER_WEB_TOKEN` | unset | Require auth for the web UI/API |
| `mastodon_instances` | 3 instances | Instances to search |
| `GITHUB_TOKEN` | unset | 60 → 5000 req/h |
| `HIBP_API_KEY` | unset | HIBP source |
| `EMAILREP_API_KEY` | unset | EmailRep source |
| `SHODAN_API_KEY` | unset | Shodan host/vuln data for `ip` |

## Development

```bash
uv run pytest                # 348 tests, no network required
uv run ruff check .
uv run ruff format --check .
```

## Deployment

**Docker / Compose**

```bash
docker build -t larpharvester:0.5.0 .
docker run --rm -p 127.0.0.1:8765:8765 \
  -v larpharvester-data:/data \
  -e LARPHARVESTER_WEB_TOKEN=change-me \
  larpharvester:0.5.0

# Compose with an optional Tor sidecar:
LARPHARVESTER_WEB_TOKEN=change-me docker compose up -d
LARPHARVESTER_WEB_TOKEN=change-me LARPHARVESTER_PROXY=socks5h://tor:9050 \
  docker compose --profile tor up -d
```

The image runs as a non-root user, stores the database in the `/data` volume, exposes port 8765,
and ships a `/healthz` healthcheck.

**systemd**

`deploy/larpharvester-web.service` serves the UI on `127.0.0.1:8765` with hardening
(`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, empty capability set).
`deploy/larpharvester-watch@.service` is a template for 24/7 monitoring:

```bash
sudo cp deploy/larpharvester-web.service /etc/systemd/system/
sudo cp deploy/larpharvester-watch@.service /etc/systemd/system/
sudo systemctl enable --now larpharvester-web
sudo systemctl enable --now larpharvester-watch@alice
```

Configuration lives in `/etc/larpharvester/env` (see `deploy/env.example`; `chmod 600`).

## Responsible use

Public data only, lawful research only. Respect each platform's terms and rate limits. Findings are
probabilistic: a `found` result means the handle exists, not that it belongs to your target; a cluster
is a hypothesis, not proof.
