## Summary

<!-- What changed and why. Link the issue if there is one. -->

## Checks

- [ ] `uv run ruff check .`
- [ ] `uv run ruff format --check .`
- [ ] `uv run pytest -q`
- [ ] `uv build --wheel`
- [ ] Added a regression test for a bug fix
- [ ] Updated docs/README/changelog when behavior changed
- [ ] No secrets, tokens, databases, or generated artifacts committed

## Privacy checklist

- [ ] No telemetry or hidden network calls
- [ ] Raw HTTP retention remains opt-in
- [ ] Sensitive identifiers are not added to cache/raw keys
- [ ] API keys stay out of URLs where the provider supports headers
- [ ] File permissions remain owner-only (`0600`/`0700`)
- [ ] Web UI remains local-first and token-gated off loopback

## Notes

<!-- Screenshots, trade-offs, follow-ups, or anything reviewers should know. -->
