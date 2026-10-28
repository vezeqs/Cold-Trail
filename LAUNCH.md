# Launch checklist

Nothing here is executed automatically. Publishing, tagging, and releases are explicit,
separate decisions. This file is the sequence to follow when you decide to ship.

## Pre-flight (local)

```bash
uv sync
uv run ruff check .
uv run ruff format --check .
uv run pytest -q
uv build --wheel
uv run coldtrail doctor --offline
```

- [ ] Tests pass; wheel includes `data/sites.toml`, templates, and static assets.
- [ ] README screenshots/GIF render on GitHub.
- [ ] No secrets, tokens, databases, or generated artifacts in the tree.
- [ ] `docs/` links, sitemap, robots, and JSON-LD validate.
- [ ] `git status` is clean.

## Repository setup

```bash
gh repo create slopmanufacturer/coldtrail --public --source=. --remote=origin --push
gh repo edit \
  --description "ColdTrail: local-first OSINT toolkit for username/email pivots, identity correlation, and evidence export." \
  --homepage "https://slopmanufacturer.github.io/coldtrail/" \
  --add-topic osint --add-topic threat-intelligence --add-topic username-enumeration \
  --add-topic email-osint --add-topic digital-forensics --add-topic python
gh api -X POST repos/slopmanufacturer/coldtrail/pages -f build_type=workflow
```

- [ ] GitHub Pages workflow succeeds; `/`, `/quickstart.html`, `/sources.html`,
      `/comparison.html`, `/privacy.html`, and `/sitemap.xml` load.
- [ ] Upload `docs/og.png` as the repository social preview.
- [ ] Replace the static tests badge in `README.md` with the CI badge after the first run.
- [ ] Enable private vulnerability reporting.
- [ ] Open the good-first issues from `GOOD_FIRST_ISSUES.md`.

## Package and container

```bash
uv build
# PyPI (choose the trusted-publishing flow in the project settings)
uv publish
# Docker
docker build -t coldtrail:0.9.0 .
docker tag coldtrail:0.9.0 ghcr.io/slopmanufacturer/coldtrail:0.9.0
docker push ghcr.io/slopmanufacturer/coldtrail:0.9.0
```

- [ ] `uvx coldtrail --version` and `pipx install coldtrail` work from a clean environment.
- [ ] Docker image runs with `COLDTRAIL_WEB_TOKEN` set; without it, the container refuses
      to bind `0.0.0.0` (expected).
- [ ] Homebrew tap/formula (optional).

## Release

```bash
git tag -a v0.9.0 -m "ColdTrail 0.9.0: privacy-first hardening"
git push origin v0.9.0
gh release create v0.9.0 --title "ColdTrail 0.9.0" --notes-file CHANGELOG.md
```

- [ ] Release notes call out privacy defaults, raw/avatar opt-in, and the rename history.
- [ ] Attach the wheel and a checksum.

## Launch posts

- [ ] **Show HN:** “Show HN: ColdTrail – local-first OSINT pivoting with evidence export”
      Body: the problem, the one-command demo, what is different, privacy defaults, limits.
- [ ] **r/OSINT:** post the comparison page and a real sample workflow; answer questions.
- [ ] **r/cybersecurity / r/netsec:** only if it meets their self-promotion rules.
- [ ] **OSINT Framework / awesome-osint:** open a small PR adding ColdTrail under tooling.
- [ ] **Mastodon / Bluesky / X:** short demo GIF, repo link, privacy note.
- [ ] **Security/OSINT Discords and local meetups:** share the demo, not a star request.

Do not mass-post the same text. Disclose that you are the maintainer. Expect “why not
Sherlock/Maigret?” and link the comparison page.

## Post-launch

- [ ] Respond to issues within 48 hours for the first week.
- [ ] Pin the release and a “start here” issue.
- [ ] Watch GitHub traffic/referrers; double down on the channel that converts.
- [ ] Add new sources/importers from real user requests before adding more UI.
- [ ] Re-run the privacy checklist after every feature PR.
