"""Generate src/larpharvester/data/sites.toml from the Sherlock project dataset.

Usage:
  python scripts/build_sites.py path/to/data.json
  python scripts/build_sites.py --fetch [--ref <git-ref>]

The generated header records the exact input (path or git ref) plus the SHA-256
of the source document, so a rebuild is reproducible.

Sherlock is MIT licensed: https://github.com/sherlock-project/sherlock
"""

from __future__ import annotations

import hashlib
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "src" / "larpharvester" / "data" / "sites.toml"
DEFAULT_SOURCE = Path("/tmp/sherlock.json")

# Pinned upstream dataset. Bump --ref to update deliberately, then commit sites.toml.
PINNED_REF = "v0.16.2"
DATA_URL = (
    "https://raw.githubusercontent.com/sherlock-project/sherlock/"
    "{ref}/sherlock_project/resources/data.json"
)


def toml_value(value: object) -> str:
    return json.dumps(value, ensure_ascii=False)


def _fetch(ref: str) -> bytes:
    url = DATA_URL.format(ref=ref)
    with urllib.request.urlopen(url, timeout=30) as response:
        return response.read()


def main() -> None:
    args = sys.argv[1:]
    if args and args[0] == "--fetch":
        ref = args[args.index("--ref") + 1] if "--ref" in args else PINNED_REF
        raw = _fetch(ref)
        source_desc = f"git ref {ref} ({DATA_URL.format(ref=ref)})"
    else:
        path = Path(args[0]) if args else DEFAULT_SOURCE
        raw = path.read_bytes()
        source_desc = f"local file {path}"
    digest = hashlib.sha256(raw).hexdigest()[:16]
    data = json.loads(raw)
    data.pop("$schema", None)

    lines = [
        "# Declarative site definitions generated from the Sherlock project dataset.",
        "# Sherlock is MIT licensed: https://github.com/sherlock-project/sherlock",
        f"# Source: {source_desc} (sha256:{digest})",
        f"# {len(data)} entries in source; POST-only entries are skipped.",
        "# Regenerate with: python scripts/build_sites.py --fetch",
        "",
    ]
    written = 0
    for name in sorted(data, key=str.casefold):
        entry = data[name]
        if not isinstance(entry, dict):
            continue
        if str(entry.get("request_method", "GET")).upper() != "GET":
            continue
        url = entry.get("urlProbe") or entry.get("url") or ""
        if "{}" not in url and "{username}" not in url:
            continue
        url = url.replace("{}", "{username}")
        probe = entry.get("urlProbe") or ""
        if probe:
            probe = probe.replace("{}", "{username}")

        lines.append(f"[sites.{toml_value(name)}]")
        lines.append(f"url = {toml_value(url)}")
        lines.append(f"main = {toml_value(entry.get('urlMain', ''))}")
        lines.append(f"error_type = {toml_value(entry.get('errorType', 'status_code'))}")
        if entry.get("errorMsg"):
            messages = entry["errorMsg"]
            if isinstance(messages, str):
                messages = [messages]
            lines.append(f"error_msg = {toml_value(messages)}")
        if entry.get("errorUrl"):
            lines.append(f"error_url = {toml_value(entry['errorUrl'])}")
        if entry.get("errorCode"):
            lines.append(f"error_code = {int(entry['errorCode'])}")
        if entry.get("regexCheck"):
            lines.append(f"regex = {toml_value(entry['regexCheck'])}")
        if probe:
            lines.append(f"url_probe = {toml_value(probe)}")
        if entry.get("headers"):
            headers = ", ".join(
                f"{toml_value(key)} = {toml_value(value)}"
                for key, value in entry["headers"].items()
            )
            lines.append(f"headers = {{ {headers} }}")
        if entry.get("isNSFW"):
            lines.append("nsfw = true")
        lines.append("")
        written += 1

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines))
    print(f"wrote {written} sites to {OUT}")


if __name__ == "__main__":
    main()
