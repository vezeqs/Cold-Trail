#!/usr/bin/env python3
"""Generate the README proof media from a real ColdTrail run.

Usage (from the repository root):

    uv run --with playwright python scripts/capture_media.py

The script ensures a demo database exists, optionally starts ``coldtrail serve``,
captures the dashboard / run / diff pages, an animated identity graph, a live
SSE pivot job, and a terminal capture of the real CLI output. It then writes
``docs/assets/manifest.json`` so ``tests/test_media_manifest.py`` can fail when
the images fall behind the code.

Requires network access for the first pivot (public sources) and Playwright's
Chromium (``python -m playwright install chromium``).
"""

from __future__ import annotations

import argparse
import hashlib
import html
import io
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "docs" / "assets"
DEFAULT_DB = Path("/tmp/coldtrail-demo.db")
FINGERPRINT_FILES = (
    "src/coldtrail/__init__.py",
    "src/coldtrail/cli/_app.py",
    "src/coldtrail/web/templates",
    "src/coldtrail/web/static",
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


def _run_cli(db: Path, target: str, sources: str | None = None) -> str:
    command = ["uv", "run", "coldtrail", "--db", str(db), "pivot", target]
    if sources:
        command.extend(["-s", sources])
    env = {
        **os.environ,
        "COLUMNS": "120",
        "TERM": "dumb",
        "NO_COLOR": "1",
        "PYTHONUNBUFFERED": "1",
    }
    completed = subprocess.run(
        command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=600, check=False
    )
    return completed.stdout + completed.stderr


def _wait_for(url: str, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.25)
    raise RuntimeError(f"server did not become ready: {url}")


def _assemble_gif(frames: list[bytes], path: Path, width: int, duration: int) -> None:
    images = []
    for frame in frames:
        image = Image.open(io.BytesIO(frame)).convert("RGB")
        ratio = width / image.width
        images.append(image.resize((width, int(image.height * ratio)), Image.Resampling.LANCZOS))
    if not images:
        raise RuntimeError("no frames captured")
    images[0].save(
        path,
        save_all=True,
        append_images=images[1:],
        duration=duration,
        loop=0,
        optimize=True,
    )


def _terminal_page(lines: list[str], title: str) -> str:
    body = html.escape("\n".join(lines))
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><style>
html,body {{ margin:0; background:#0b0f14; }}
.term {{ font: 13px/1.45 "DejaVu Sans Mono", monospace; color:#d7dde7;
         background:#0b0f14; padding:18px 22px; white-space:pre; }}
.bar {{ height:34px; background:#151b24; display:flex; align-items:center;
        padding:0 14px; color:#8b97a8; font:12px "DejaVu Sans Mono", monospace;
        border-bottom:1px solid #232a36; }}
.dot {{ width:10px; height:10px; border-radius:50%; margin-right:6px; display:inline-block; }}
</style></head><body>
<div class="bar"><span class="dot" style="background:#ff5f56"></span>
<span class="dot" style="background:#ffbd2e"></span>
<span class="dot" style="background:#27c93f"></span>&nbsp;&nbsp;{html.escape(title)}</div>
<div class="term">{body}</div>
</body></html>"""


def _capture(base: str, db: Path, target: str) -> dict[str, object]:
    from playwright.sync_api import sync_playwright

    ASSETS.mkdir(parents=True, exist_ok=True)
    captured: list[str] = []

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 1000})

        page.goto(base, wait_until="networkidle")
        page.screenshot(path=str(ASSETS / "web-dashboard.png"))
        captured.append("web-dashboard.png")

        runs = json.loads(urllib.request.urlopen(f"{base}/api/runs", timeout=10).read().decode())[
            "runs"
        ]
        if len(runs) < 2:
            _run_cli(db, target, sources="github,gitlab,reddit,hackernews,keybase")
            runs = json.loads(
                urllib.request.urlopen(f"{base}/api/runs", timeout=10).read().decode()
            )["runs"]
        run_id = runs[0]["id"]

        page.goto(f"{base}/runs/{run_id}", wait_until="networkidle")
        canvas = page.locator("#identity-graph")
        canvas.scroll_into_view_if_needed()
        page.wait_for_timeout(250)
        graph_frames = []
        for _ in range(30):
            graph_frames.append(canvas.screenshot())
            page.wait_for_timeout(70)
        _assemble_gif(graph_frames, ASSETS / "web-graph.gif", width=820, duration=70)
        captured.append("web-graph.gif")

        page.wait_for_timeout(2500)
        page.evaluate("window.scrollTo(0, 0)")
        page.screenshot(path=str(ASSETS / "web-run.png"))
        captured.append("web-run.png")

        def profile_counts() -> dict[int, int]:
            listing = json.loads(
                urllib.request.urlopen(f"{base}/api/runs", timeout=10).read().decode()
            )["runs"]
            counts: dict[int, int] = {}
            for item in listing[:12]:
                try:
                    payload = json.loads(
                        urllib.request.urlopen(f"{base}/api/runs/{item['id']}", timeout=10)
                        .read()
                        .decode()
                    )
                except OSError:
                    continue
                counts[item["id"]] = len(payload.get("profiles") or [])
            return counts

        counts = profile_counts()
        if len(counts) < 2 or len(set(counts.values())) < 2:
            _run_cli(db, target, sources="github")
            counts = profile_counts()
        if len(counts) >= 2:
            small = min(counts, key=counts.get)
            large = max(counts, key=counts.get)
            page.goto(f"{base}/diff?a={small}&b={large}", wait_until="networkidle")
            page.screenshot(path=str(ASSETS / "web-diff.png"))
            captured.append("web-diff.png")

        page.goto(f"{base}/pivot", wait_until="networkidle")
        page.fill('input[name="target"]', target)
        page.select_option('select[name="scope"]', "curated")
        page.click('button[type="submit"]')
        page.wait_for_url("**/jobs/*", timeout=30_000)
        pivot_frames = []
        for _ in range(50):
            pivot_frames.append(page.screenshot())
            if "/jobs/" not in page.url:
                break
            try:
                state = page.locator("#job-state").inner_text(timeout=500).strip()
            except Exception:
                state = ""
            if state in {"done", "error"}:
                break
            page.wait_for_timeout(80)
        _assemble_gif(pivot_frames, ASSETS / "web-pivot.gif", width=980, duration=120)
        captured.append("web-pivot.gif")

        browser.close()

    cli_text = _run_cli(db, target)
    cli_lines = [line.rstrip() for line in cli_text.splitlines()]
    cli_lines = [line for line in cli_lines if line.strip()]
    stop = next(
        (index for index, line in enumerate(cli_lines) if "non-matching checks hidden" in line),
        min(len(cli_lines) - 1, 30),
    )
    cli_lines = cli_lines[: stop + 1]
    terminal = _terminal_page(cli_lines, f"coldtrail pivot {target}")

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1180, "height": 860})
        page.set_content(terminal)
        page.screenshot(path=str(ASSETS / "cli-pivot.png"))
        captured.append("cli-pivot.png")

        frames = []
        step = max(1, len(cli_lines) // 24)
        for index in range(1, len(cli_lines) + 1, step):
            page.set_content(_terminal_page(cli_lines[:index], f"coldtrail pivot {target}"))
            frames.append(page.screenshot())
        page.set_content(terminal)
        frames.append(page.screenshot())
        _assemble_gif(frames, ASSETS / "cli-pivot.gif", width=980, duration=220)
        captured.append("cli-pivot.gif")
        browser.close()

    version_match = re.search(
        r'__version__\s*=\s*"([^"]+)"',
        (ROOT / "src" / "coldtrail" / "__init__.py").read_text(encoding="utf-8"),
    )
    return {
        "version": version_match.group(1) if version_match else "",
        "target": target,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "assets": {name: _sha256((ASSETS / name).read_bytes()) for name in captured},
        "code_fingerprint": _code_fingerprint(),
        "note": "Generated by scripts/capture_media.py from a live pivot.",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--target", default="octocat")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--base-url", default="")
    parser.add_argument("--skip-pivot", action="store_true")
    args = parser.parse_args()

    db: Path = args.db.expanduser()
    if not db.exists():
        db.parent.mkdir(parents=True, exist_ok=True)
        if not args.skip_pivot:
            print(f"seeding {db} with a live pivot for {args.target}…", file=sys.stderr)
            _run_cli(db, args.target)

    base = args.base_url.rstrip("/")
    server = None
    if not base:
        base = f"http://127.0.0.1:{args.port}"
        print(f"starting coldtrail serve on {base}…", file=sys.stderr)
        server = subprocess.Popen(
            [
                "uv",
                "run",
                "coldtrail",
                "--db",
                str(db),
                "--no-cache",
                "serve",
                "--port",
                str(args.port),
                "--log-level",
                "warning",
            ],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            _wait_for(f"{base}/healthz")
            manifest = _capture(base, db, args.target)
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
    else:
        _wait_for(f"{base}/healthz")
        manifest = _capture(base, db, args.target)

    (ASSETS / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {ASSETS / 'manifest.json'} and {len(manifest['assets'])} assets")
    return 0


if __name__ == "__main__":
    sys.exit(main())
