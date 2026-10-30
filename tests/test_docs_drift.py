"""Guards against README/AGENTS drifting from the code surface."""

from __future__ import annotations

import re
from pathlib import Path

from coldtrail.cli import app
from coldtrail.config import Settings
from coldtrail.sources import SOURCES
from coldtrail.store.schema import SCHEMA_VERSION
from coldtrail.web import create_app

ROOT = Path(__file__).resolve().parent.parent


def test_readme_source_count_matches_runtime():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    match = re.search(r"Pivot across (\d+) sources", readme)
    assert match, "README is missing the source-count sentence"
    assert int(match.group(1)) == len(SOURCES) == 482


def test_agents_command_and_schema_counts_match():
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    commands = re.search(r"\((\d+) top-level commands", agents)
    assert commands, "AGENTS.md is missing the command-count sentence"
    assert int(commands.group(1)) == len(app.registered_commands)
    schema = re.search(r"SCHEMA_VERSION \((\d+)\)", agents)
    assert schema, "AGENTS.md is missing the schema-version note"
    assert int(schema.group(1)) == SCHEMA_VERSION


def test_agents_lists_recent_modules():
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    for module in ("websearch.py", "company.py", "security.py", "alerts.py"):
        assert module in agents


def test_documented_web_routes_exist(tmp_path):
    settings = Settings(db_path=tmp_path / "drift.db")
    application = create_app(settings)
    paths = {getattr(route, "path", "") for route in application.routes}
    for path in (
        "/",
        "/runs",
        "/runs/{run_id}",
        "/search",
        "/sources",
        "/cases",
        "/tools",
        "/pivot",
        "/help",
        "/login",
        "/logout",
        "/healthz",
        "/evidence/{attachment_id}",
        "/api/health",
        "/api/search",
        "/api/sources",
        "/api/pivot",
        "/api/jobs/{job_id}/stream",
    ):
        assert path in paths, f"documented route {path} is missing"
