# Good first issues

Candidate issues to open after the repository is published. Each is scoped, testable, and
does not require a paid API key.

1. **Add a source: Threads post harvesting**
   - Area: source, social
   - Add `posts()` for Threads where public metadata allows it.
   - Tests: found/missing/blocked with `respx`; contract fixture.

2. **Add a source: Pinterest profile metadata depth**
   - Area: source, social
   - Parse follower count and website from the profile page.
   - Tests: found/missing/login-wall.

3. **Add a source: Bluesky handle-history display**
   - Area: source, UI
   - Surface `handle_history` in the run page and export.
   - Tests: store + web render.

4. **Add an importer: Blackbird CSV**
   - Area: integrations
   - Normalize Blackbird CSV to profiles/entities.
   - Tests: fixture + `INGEST_FORMATS` detection.

5. **Add an importer: Maigret NDJSON**
   - Area: integrations
   - Parse `--json ndjson` output, not only `simple`.
   - Tests: multi-line JSON fixture.

6. **Add a `--since` filter to `timeline`**
   - Area: CLI/query
   - Accept ISO timestamps and filter before sorting.
   - Tests: boundary timestamps.

7. **Add CSV export for `diff`**
   - Area: CLI/report
   - Export added/removed/changed rows in a flat CSV.
   - Tests: header and row counts.

8. **Add a `doctor` check for config file permissions**
   - Area: privacy/ops
   - Warn when `config.toml` is group/world-readable.
   - Tests: mode `0644` vs `0600`.

9. **Add a TUI "copy command" action**
   - Area: TUI
   - Copy the equivalent CLI command for the focused row.
   - Tests: pilot action and clipboard fallback.

10. **Add a docs page for case dossiers**
    - Area: docs
    - Walk through case creation, tags, notes, evidence, and STIX export.
    - Add to `docs/sitemap.xml` and nav.

## How to claim one

Comment on the issue with your approach. Keep the PR focused, add an offline regression test,
and run the checks in [CONTRIBUTING.md](CONTRIBUTING.md).
