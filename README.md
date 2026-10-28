# larpharvester

**Local-first OSINT toolkit for usernames, emails, and public profiles.**
Pivot across 482 sources, harvest profiles/posts into SQLite, correlate identities, and export
evidence-grade dossiers — from a CLI, a TUI, or a local web UI.

[![CI](https://github.com/slopmanufacturer/larpharvester/actions/workflows/ci.yml/badge.svg)](https://github.com/slopmanufacturer/larpharvester/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Docs](https://img.shields.io/badge/docs-GitHub%20Pages-2ea44f.svg)](https://slopmanufacturer.github.io/larpharvester/)

## Quickstart

```bash
git clone https://github.com/slopmanufacturer/larpharvester
cd larpharvester
uv sync

uv run larpharvester pivot alice          # curated sources + correlation
uv run larpharvester pivot alice --web    # add the 432-site web corpus
uv run larpharvester serve --open         # local web UI at 127.0.0.1:8765
uv run larpharvester tui                  # terminal UI
```

No API keys are required for most sources. Optional keys unlock more coverage:

```bash
export GITHUB_TOKEN=...        # higher GitHub rate limits
export HIBP_API_KEY=...        # Have I Been Pwned
export EMAILREP_API_KEY=...
export HUNTER_API_KEY=...      # Hunter.io email verification
export X_BEARER_TOKEN=...      # X/Twitter API v2
```

## What you get

| Capability | Details |
| --- | --- |
| **Pivot** | 482 sources (50 curated sources + 432 declarative sites), handle/email variants, multi-hop expansion |
| **Harvest** | Profiles, paginated posts, follow graphs, incremental cursors, profile-change history |
| **Correlate** | Additive scoring, calibrated confidence, Jaro-Winkler handle similarity, clusters |
| **Investigate** | Domain/IP/phone, RDAP, DNS, crt.sh, TLS, BGP/ASN, Wayback, dorks, breach metadata |
| **Collect evidence** | Content-addressed SHA-256 blobs, case dossiers, tags, notes, audit log |
| **Export** | JSON, JSONL, CSV, GraphML, GEXF, DOT, HTML, Markdown, STIX 2.1, Maltego |
| **Automate** | `batch`, `watch`, `recluster`, `diff`, JSON output everywhere |

### Three interfaces, one database

- **CLI** — scriptable Typer app with grouped help and JSON/JSONL output.
- **TUI** — Textual console with dashboard, live pivot rows, browse/search, cases, tools.
- **Web** — FastAPI app with JSON API, SSE-streamed pivots, interactive identity graph,
  OSINT workbench, run diffing, case dossiers, evidence downloads, optional auth.

```bash
uv run larpharvester --help
uv run larpharvester serve --token "$(openssl rand -hex 24)"   # shared-token auth
```

## External tools

Already installed tools are detected and can be imported into the same database:

```bash
uv run larpharvester integrations                  # status + install hints
uv run larpharvester run maigret alice --json      # import findings
uv run larpharvester ingest spiderfoot.json        # auto-detect format
```

| Category | Tools |
| --- | --- |
| Username | `sherlock`, `maigret`, `naminter` (WhatsMyName), `social-analyzer`, `blackbird` |
| Email | `holehe`, `h8mail`, `ghunt` |
| Social | `instaloader` (Instagram), `twscrape` (X/Twitter) |
| Infrastructure | `theHarvester`, `subfinder`, `whois`, `dig`, `nmap` |
| Files/media | `exiftool`, `yt-dlp` |
| Import-only | SpiderFoot JSON, Maltego CSV, theHarvester JSON, generic JSON |

Every runner uses an argument vector (never a shell) and rejects option-like targets.

## Documentation

- **Site:** <https://slopmanufacturer.github.io/larpharvester/>
- **Quickstart:** <https://slopmanufacturer.github.io/larpharvester/quickstart.html>
- **Source & integration coverage:** <https://slopmanufacturer.github.io/larpharvester/sources.html>
- **Security policy:** [SECURITY.md](SECURITY.md)
- **Changelog:** [CHANGELOG.md](CHANGELOG.md)

## Safety and legal

larpharvester collects **public data only** and is built for authorized research,
journalism, threat intelligence, and defensive security. You are responsible for
applicable law, platform terms, and scope authorization.

- Default bind is `127.0.0.1`; the web UI has no auth unless `--token` is set.
- Rate limiting and pacing are on by default; `--respect-robots` is available.
- Breach features are lookup-only metadata; they never retrieve or crack credentials.
- Pwned Passwords uses k-anonymity and never sends the password or full hash.

## Development

```bash
uv sync
uv run pytest                  # 455 tests, no network (respx/TestClient/Textual pilot)
uv run ruff check .
uv run ruff format --check .
uv run larpharvester doctor
```

Python 3.11+, `uv`, `src/` layout. Tests never hit the network; source contracts replay
recorded fixtures. See [AGENTS.md](AGENTS.md) for architecture and contribution rules.

## License

MIT. The declarative corpus is generated from the
[Sherlock](https://github.com/sherlock-project/sherlock) dataset (MIT); see
`src/larpharvester/data/sites.toml` for the pinned ref and checksum.
