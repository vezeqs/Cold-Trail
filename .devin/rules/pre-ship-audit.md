---
description: "Mandatory systematic debug, security, privacy, and production audit before shipping."
trigger: always_on
---

# Pre-ship audit is mandatory

Before **any** push, tag, release, package publish, container publish, or deployment:

1. Invoke the `pre-ship-audit` skill and follow it end to end.
2. Reproduce and fix every bug, security issue, privacy regression, broken link, and failed check you find.
3. Re-run the full verification suite after fixes. Do not ship with failing tests, lint, build, or docs validation.
4. Report the evidence: commands run, results, commit hash, and any remaining known limitations.
5. Get explicit approval for the specific remote-visible action. Never use `--no-verify` or bypass checks.

If a check cannot be run, say so and do not claim the release is verified.
