# ColdTrail audit — 2026-10-30

> Newer record: [AUDIT-2026-10-31.md](AUDIT-2026-10-31.md) (independent pass,
> 20 findings: 19 fixed, 1 not a bug).

Baseline: `master` @ `86fc516` (v0.9.0), 526 tests, ruff/mypy/bandit clean.
Scope: security, privacy, correctness, export integrity, documentation claims.
Method: manual review of every high-risk module (`http.py`, `web/`, `store/`,
`report.py`, `evidence.py`, `pivot.py`, `harvest.py`, `watch.py`, `analysis.py`,
`integrations.py`, `contracts.py`), plus CodeQL alerts, Bandit, pip-audit, and
targeted repro scripts. Every fixed finding below names its regression test in
`tests/test_audit_fixes.py`.

Severity: **H** high, **M** medium, **L** low. Status: **fixed** in this branch,
**documented** (accepted limitation), or **open** (needs a design decision).

## Summary

| # | Sev | Area | Finding | Status |
| --- | --- | --- | --- | --- |
| 1 | H | Web | `/healthz` and `/api/health` return raw exception text (DB path/SQLite internals) to unauthenticated clients | fixed |
| 2 | H | Export | GraphML and GEXF emit invalid XML when a username/display name contains `"` (attribute injection) | fixed |
| 3 | H | HTTP | A 200 bot-wall page is written to `http_cache` before the WAF check, and cache hits skip the check — a challenge page is replayed as a valid profile | fixed |
| 4 | H | Privacy | The SQLite file is created with the process umask before `chmod 0600`, leaving a readable window on shared hosts | fixed |
| 5 | M | Web | `POST /pivot` and `POST /api/pivot` accept a whitespace-only target; after `.strip()` it probes every source with an empty handle | fixed |
| 6 | M | HTTP | Cache key ignores `Accept`, so a JSON request can be served a cached HTML body (and vice versa) | fixed |
| 7 | M | HTTP | Cached bodies are always decoded as UTF-8; pages served as ISO-8859-1/Windows-1252 become mojibake | fixed |
| 8 | M | Report | HTML dossier sorts posts lexicographically by `created_at`, violating the project's own timestamp invariant | fixed |
| 9 | M | Harvest | `harvest`/`watch` pick the oldest/newest post with `min()`/`max()` on display strings; offsets make the window wrong | fixed |
| 10 | M | Evidence | `add_evidence` hashes the file after reading it (TOCTOU); a changed file can be stored under the wrong digest | fixed |
| 11 | M | Evidence | `evidence_path()`/`prune()` join an unvalidated `sha256` from the DB into a filesystem path | fixed |
| 12 | M | Privacy | `doctor` prints the proxy URL verbatim, including `user:password@` credentials, and the audit log persists it | fixed |
| 13 | M | HTTP | Redirects are followed without re-checking the destination host, so a public URL can redirect into loopback/link-local | fixed |
| 14 | M | Analysis | The Telegram entity regex matches Matrix IDs (`@alice:matrix.org`), producing a phantom Telegram handle | fixed |
| 15 | L | Web | Search page reflects the FTS exception text into the page | fixed |
| 16 | L | CLI | A corrupt database raises an uncaught `sqlite3` traceback from the audit hook; corrupt JSON rows crash reads | fixed |
| 17 | L | Cases | Case creation accepts a whitespace-only name | fixed |
| 18 | L | Report | DOT export writes `weight=None` when a link has no score | fixed |
| 19 | L | Report | Markdown export lets `|`/newlines from harvested text break tables | fixed |
| 20 | L | Docs | README claims 521 tests; the suite has 526. AGENTS claims 58 leaf commands; there are 59 | fixed |
| 21 | L | Privacy | `doctor` reports config-file mode but never warns when it is group/world-readable | fixed |
| 22 | L | Docs | `GOOD_FIRST_ISSUES.md` lists work that already shipped (`timeline --since`, config-permission check) | fixed (removed) |
| 23 | — | HTTP | `is_public_host` returns `True` on DNS failure and validation is TOCTOU (DNS rebinding) | documented |
| 24 | — | Sources | Mastodon/Nostr/domain/avatar probes use `resolve=False`, which skips DNS for the initial host | documented |
| 25 | — | Analysis | Posting-hour timezone inference is ambiguous by 24h, so UTC+12/+13/+14 are not distinguishable from UTC-12/-11/-10 | documented |
| 26 | — | Correlate | Pair scoring is O(n²); a full 482-source pivot is ~116k pair evaluations | documented |
| 27 | L | TUI | `textual` 8.x removed `Static.renderable`; 7 TUI tests failed | fixed |
| 28 | L | Web UI | The identity graph's force layout collapsed nodes into an unreadable center hub with overlapping labels | fixed (visual) |
| 29 | L | Evidence | `add_evidence` used a production `assert` for an input guard, which disappears under `python -O` | fixed |

## Details and fixes

### 1. Health endpoint leaks exception text (H)

**Claim:** `/healthz` is safe to expose to a container probe and returns no
internal detail.
**Evidence:** `web/api_routes.py` built `detail = f"{type(exc).__name__}: {exc}"`
and returned it from `/healthz` and `/api/health`, both in `PUBLIC_PATHS`. A
failed `SELECT 1` can disclose the database path and SQLite internals. CodeQL
alerts #1/#2 (`py/stack-trace-exposure`).
**Cause:** exception text was treated as a user-facing message.
**Fix:** return a fixed `"database unavailable"`, log the exception server-side,
keep the 503 status.
**Test:** `test_health_does_not_leak_exception_text`.

### 2. GraphML/GEXF attribute injection (H)

**Claim:** graph exports are valid XML.
**Evidence:** `report.py` used `xml.sax.saxutils.escape()` for attribute values.
`escape()` handles `&`, `<`, `>` but not `"`. A profile with username `a"b`
produced `<node id="x:a"b">`; `ElementTree.fromstring` rejects it. Reproduced
with a display name containing a quote and a NUL.
**Cause:** text escaping used for attribute values.
**Fix:** `quoteattr()` for every attribute and strip XML-illegal control
characters.
**Test:** `test_graphml_and_gexf_escape_quotes_and_controls`.

### 3. Cached WAF pages bypass the block check (H)

**Claim:** a bot wall is reported as `blocked` on every run.
**Evidence:** `Fetcher._request()` called `_cache_put()` before
`_looks_blocked()`. A 200 challenge page was stored, the first call raised
`BlockedError`, and the second call returned the cached challenge as a normal
200.
**Cause:** cache write happened before the WAF classification.
**Fix:** classify before caching and re-check cached responses.
**Test:** `test_blocked_pages_are_not_cached` (asserts two upstream requests).

### 4. SQLite file creation window (H)

**Claim:** the DB and sidecars are owner-only from the moment they exist.
**Evidence:** `StoreBase.__init__` called `sqlite3.connect(path)` and only then
`_secure_files()`. With umask `022`, the DB exists as `0644` until the chmod.
**Cause:** permissions were repaired after creation instead of set at creation.
**Fix:** run `mkdir`/`connect` under `umask(0o077)` and restore it in `finally`.
**Test:** `test_store_creates_private_database_and_parent` (asserts `0600` file
and `0700` parent for a nested path).

### 5. Empty target after strip (M)

**Claim:** a pivot always has a target.
**Evidence:** `target: Form(min_length=1)` accepts `" "`. Both pivot endpoints
then call `target.strip()` and start a job with `""`; declarative sites whose
template becomes the site root return 200 and are recorded as `found`.
**Cause:** validation ran before trimming.
**Fix:** validate the trimmed value in the web layer and in `pivot()`,
`harvest()`, and `collect_follows()`.
**Test:** `test_pivot_rejects_blank_target`, `test_harvest_rejects_blank_username`,
`test_web_pivot_rejects_blank_target`.

### 6. Cache key ignores Accept (M)

**Claim:** cached responses are safe to reuse for the same URL.
**Evidence:** `_cache_key(url, params)` ignored request headers. `get_json()`
and `get_text()` on the same URL share a row; a cached HTML body can be
returned to `get_json()` and raise a spurious `BlockedError`.
**Cause:** cache identity was URL-only.
**Fix:** the HTTP-cache key includes `Accept`; raw/replay keys stay URL-only so
recorded fixtures still work.
**Test:** `test_cache_varies_by_accept` (asserts two upstream requests and a
JSON body).

### 7. Cached charset (M)

**Claim:** a cached body is byte-identical to the live body.
**Evidence:** `_from_cache()` decoded with UTF-8 regardless of the stored
`content_type`. A `charset=iso-8859-1` body turned `café` into `caf�`.
**Cause:** decoding ignored the stored content type.
**Fix:** parse `charset` and decode with it, falling back to UTF-8.
**Test:** `test_cached_body_uses_stored_charset` (asserts one upstream request
and the correct text on both reads).

### 8. HTML dossier timestamp ordering (M)

**Claim:** the report's timeline is chronological.
**Evidence:** `to_html()` sorted by `created_at` strings. Reproduced with
`10:00+14:00` (2023-12-31T20:00Z) and `09:00-12:00` (2024-01-01T21:00Z); the
lexicographic order put the later post first. This is the defect AGENTS.md says
must never happen.
**Cause:** display strings used as sort keys.
**Fix:** sort by `utils.epoch_seconds()`, `None` last.
**Test:** `test_html_report_orders_posts_chronologically` (and the Markdown
report now uses the same helper).

### 9. Harvest/watch window selection (M)

**Claim:** `--incremental` resumes from the newest post and tombstones only
posts older than the fetched window.
**Evidence:** `cli/collect.py` and `watch.py` used `min()`/`max()` over
`created_at` display strings. With mixed offsets the earliest post was chosen
as `2024-01-01T09:00:00-12:00` instead of `2024-01-01T10:00:00+14:00`.
**Cause:** same display-string ordering defect as #8.
**Fix:** choose the boundary and cursor by `epoch_seconds()`.
**Test:** `test_harvest_window_uses_chronological_order`,
`test_watch_window_uses_chronological_order`.

### 10. Evidence hash TOCTOU (M)

**Claim:** the blob name is the SHA-256 of the blob bytes.
**Evidence:** `add_evidence` read the file, then hashed the path a second time.
A file modified between the two reads is stored under a digest that does not
match its bytes.
**Cause:** two independent reads of the same path.
**Fix:** hash the bytes that were actually read.
**Test:** `test_evidence_hashes_the_bytes_it_reads` (monkeypatches
`Path.read_bytes` to return different bytes than the file on disk).

### 11. Evidence path traversal (M)

**Claim:** evidence blobs stay under `<db dir>/evidence/`.
**Evidence:** `evidence_path()` and `prune()` joined an unvalidated `sha256`
from `attachments` into a path. A hand-edited row of `../../etc/passwd`
escapes the directory.
**Cause:** DB values trusted as path components.
**Fix:** require exactly 64 lowercase hex characters before joining; report
invalid rows in `verify_evidence` and skip them in `prune`.
**Test:** `test_evidence_path_rejects_invalid_digest`.

### 12. Proxy credentials in doctor and audit (M)

**Claim:** `doctor --json` and `coldtrail audit` never print secrets.
**Evidence:** `settings.proxy` was emitted verbatim in two places; a proxy URL
of `http://user:s3cret@host` printed the password. The audit hook also stored
`--proxy` argv unchanged.
**Cause:** proxy URLs were treated as non-secret.
**Fix:** redact userinfo in `doctor`, add `--proxy` to `SENSITIVE_FLAGS`.
**Test:** `test_doctor_redacts_proxy_credentials` (checks both stdout and the
audit table).

### 13. Redirect SSRF (M)

**Claim:** a public target cannot reach loopback/link-local.
**Evidence:** `httpx.AsyncClient(follow_redirects=True)` follows redirects
without re-validating the destination. A public URL can redirect to
`http://127.0.0.1:…`.
**Cause:** only the initial URL was checked.
**Fix:** reject a final URL whose host is a literal private address, loopback,
`.local`, or `localhost` when private targets are not explicitly allowed.
**Test:** `test_redirect_to_loopback_is_blocked`.

### 14. Matrix ID counted as Telegram (M)

**Claim:** entity kinds are accurate.
**Evidence:** the Telegram regex ended with `\b`, which matches before `:`, so
`@alice:matrix.org` produced both a `matrix` and a `telegram` entity.
**Cause:** no delimiter guard after the handle.
**Fix:** add a negative lookahead for `:`.
**Test:** `test_matrix_ids_are_not_telegram_handles`.

### 15–22. Low-severity fixes

- **Search page (#15):** log the exception and show `invalid query` only.
  **Test:** `test_search_page_does_not_reflect_exception_text`.
- **Corrupt DB/JSON (#16):** the audit hook catches `sqlite3.Error`; row
  helpers return `{}`/`[]` for corrupt JSON instead of raising.
  **Test:** `test_cli_survives_audit_log_failure`,
  `test_corrupt_json_rows_do_not_crash_queries`.
- **Case names (#17):** `Store.create_case` rejects empty/whitespace and names
  over 120 characters; the web route rejects a blank add-run name.
  **Test:** `test_case_names_reject_whitespace`.
- **DOT (#18):** missing scores default to `0.0`.
  **Test:** `test_dot_export_handles_missing_score`.
- **Markdown (#19):** table cells escape `|` and collapse newlines; the
  Markdown timeline uses the chronological helper.
  **Test:** `test_markdown_tables_escape_pipes_and_newlines`.
- **Docs (#20):** README no longer hardcodes a test count; AGENTS.md records 48
  top-level / 61 leaf commands; `test_docs_drift.py` guards both. The Pages
  JSON-LD `softwareVersion` was also stale at 0.9.0 and now matches 0.10.0.
- **Config permissions (#21):** `doctor` warns and sets
  `privacy.config_mode_warning` when the config is group/world-readable.
  **Test:** `test_doctor_warns_about_world_readable_config`.
- **Stale docs (#22):** `GOOD_FIRST_ISSUES.md` (two items already shipped) and
  `LAUNCH.md` (pre-launch scaffolding) removed; release guidance folded into
  CONTRIBUTING.md.
- **Production assert (#29):** `add_evidence` narrowed `source_path` with
  `assert source_path is not None` after an earlier guard. `python -O` strips
  asserts, so the guard is now an explicit `ValueError`.
  **Test:** `test_evidence_hashes_the_bytes_it_reads` exercises the path branch.
- **Graph layout (#28):** the force simulation's repulsion was too weak against
  the centering force, so a hub-and-spoke graph collapsed into one unreadable
  cluster. Raised repulsion, lowered centering, lengthened link targets, drew
  label halos, and let the simulation run longer. This is a visual fix; it is
  guarded by `tests/test_media_manifest.py` (the screenshot cannot drift from
  the UI code) rather than a unit assertion about node positions.

## Accepted limitations (not fixed here)

- **DNS rebinding / TOCTOU.** Validation resolves a host once; the request may
  resolve it again. Closing this needs a pinned-IP transport or a resolver hook.
  Documented in SECURITY.md.
- **`resolve=False` in source probes.** Mastodon/Nostr/domain/avatar checks skip
  DNS for the initial host to keep offline tests deterministic. The web layer
  calls `ensure_public_target()` (with DNS) first, and the CLI exposes
  `--allow-private-targets` for authorized internal recon.
- **Timezone inference ambiguity.** Posting-hour analysis recovers the offset
  modulo 24 hours; UTC+13 and UTC-11 have the same activity pattern. The
  inference reports the conventional `-12..+11` band and is labelled as a hint,
  not a fact.
- **O(n²) correlation.** 482 profiles produce ~116k pair evaluations; measured
  runs are still dominated by network time. A blocking/index pass is a future
  optimisation, not a correctness bug.
- **Textual 8 (#27):** the TUI source already used supported `Static.update()`
  calls; only the tests read `.renderable`. Added `_static_text()` in
  `tests/test_tui.py` (renderable → content → render). The full suite passes on
  Textual 2.1.2 and 8.2.8. **Test:** `tests/test_tui.py` (15 passed on both).

## False positives

- CodeQL #3/#4 (`py/weak-sensitive-data-hashing`) flag the SHA-1 prefix in
  `breach.sha1_prefix`. SHA-1 is required by the Pwned Passwords k-anonymity
  protocol; the call already passes `usedforsecurity=False`, and only five hex
  characters leave the machine. Dismiss, do not "fix".
