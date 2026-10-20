# larpharvester

OSINT CLI for **pivoting** usernames and emails across public sources, **harvesting** profiles and
posts into a local SQLite database, **correlating** them into inferred identities, and **reporting**
the result as JSON, CSV, GraphML, GEXF, DOT, or a self-contained HTML dossier.

488 sources out of the box: 28 hand-written API sources plus 460 declarative definitions generated
from the [Sherlock](https://github.com/sherlock-project/sherlock) dataset (MIT). No API keys needed
for most of it; optional keys unlock GitHub rate limits, HIBP, and EmailRep.

## Install

```bash
uv sync
uv run larpharvester --help
```

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
uv run larpharvester phone "+351 912 345 678"        # carrier, region, timezone
uv run larpharvester ip 8.8.8.8                       # PTR, reverse IP, Shodan (optional key)
uv run larpharvester archive https://example.com/    # Wayback CDX captures
uv run larpharvester archive https://example.com/ --snapshot 20200101000000
```

## Sources

| Group | Sources |
| --- | --- |
| `social` | reddit, hackernews, mastodon, bluesky, telegram, youtube, twitch, steam, chesscom, lichess, roblox, duolingo |
| `dev` | github, gitlab, codeberg, stackoverflow, kaggle, huggingface, npm, pypi, devto, hackerone |
| `email` | gravatar, keybase, pgp (keyserver.ubuntu.com), github-commits, hibp, emailrep |
| `web` | 460 declarative sites (Sherlock corpus), selectable with `--web` or `-g web` |

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
| Shared extracted entity (email, crypto, phone, chat handle) | 0.8 |
| Same display name | 0.3 |
| Accounts created within 7 days | 0.1 |
| Same inferred timezone | 0.1 |
| Same language | 0.05 |
| Timezone difference ≥ 4h | −0.1 |
| Language mismatch | −0.05 |

Coverage is reported explicitly (`found / not_found / blocked / error`), so a bot wall never looks
like an absence.

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
| `mastodon_instances` | 3 instances | Instances to search |
| `GITHUB_TOKEN` | unset | 60 → 5000 req/h |
| `HIBP_API_KEY` | unset | HIBP source |
| `EMAILREP_API_KEY` | unset | EmailRep source |
| `SHODAN_API_KEY` | unset | Shodan host/vuln data for `ip` |

## Development

```bash
uv run pytest                # 209 tests, no network required
uv run ruff check .
uv run ruff format --check .
```

## Responsible use

Public data only, lawful research only. Respect each platform's terms and rate limits. Findings are
probabilistic: a `found` result means the handle exists, not that it belongs to your target; a cluster
is a hypothesis, not proof.
