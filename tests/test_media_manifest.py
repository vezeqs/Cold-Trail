"""Fail when the generated README media fall behind the code."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from coldtrail import __version__

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "docs" / "assets"
FINGERPRINT_FILES = (
    "src/coldtrail/__init__.py",
    "src/coldtrail/cli/_app.py",
    "src/coldtrail/web/templates",
    "src/coldtrail/web/static",
)


def _code_fingerprint() -> str:
    digest = hashlib.sha256()
    for relative in FINGERPRINT_FILES:
        path = ROOT / relative
        candidates = [path] if path.is_file() else sorted(path.rglob("*"))
        for candidate in candidates:
            if candidate.is_file():
                digest.update(candidate.relative_to(ROOT).as_posix().encode())
                digest.update(candidate.read_bytes())
    return digest.hexdigest()


def test_manifest_matches_assets_and_code():
    manifest = json.loads((ASSETS / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["version"] == __version__
    assert manifest["code_fingerprint"] == _code_fingerprint(), (
        "UI files changed; regenerate docs/assets with "
        "`uv run --with playwright python scripts/capture_media.py`"
    )
    for name, expected in manifest["assets"].items():
        path = ASSETS / name
        assert path.is_file(), f"missing generated asset: {name}"
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected, (
            f"{name} was edited by hand; regenerate it with scripts/capture_media.py"
        )


def test_readme_references_generated_assets():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    manifest = json.loads((ASSETS / "manifest.json").read_text(encoding="utf-8"))
    for name in manifest["assets"]:
        assert name in readme, f"README does not reference docs/assets/{name}"
