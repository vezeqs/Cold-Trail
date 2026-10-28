"""Tests for the new CLI features: timeline filters, ip limit, case JSON."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from coldtrail.cli import app
from coldtrail.models import Post, Profile
from coldtrail.store import Store

runner = CliRunner()


def _seed(tmp_path):
    db = tmp_path / "features.db"
    with Store(db) as store:
        run_id = store.start_run("harvest", "alice")
        store.save_profiles(run_id, [Profile("github", "alice", "https://github.com/alice")])
        store.save_posts(
            run_id,
            [
                Post("github", "alice", "p1", "https://x/p1", "2024-01-01T00:00:00Z", "one"),
                Post("github", "alice", "p2", "https://x/p2", "2024-01-02T00:00:00Z", "two"),
                Post("github", "alice", "p3", "https://x/p3", "2024-01-03T00:00:00Z", "three"),
            ],
        )
        store.finish_run(run_id)
    return db


def test_timeline_since_and_until(tmp_path):
    db = _seed(tmp_path)
    result = runner.invoke(
        app,
        [
            "--db",
            str(db),
            "timeline",
            "--since",
            "2024-01-02T00:00:00Z",
            "--until",
            "2024-01-02T23:59:59Z",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    rows = json.loads(result.output)
    assert [row["post_id"] for row in rows] == ["p2"]


def test_ip_limit_is_applied(tmp_path, monkeypatch):
    async def fake_reverse(fetcher, address, key=None):
        return ["a.example", "b.example", "c.example"]

    async def fake_ptr(fetcher, address):
        return []

    async def fake_shodan(fetcher, address, key=None):
        return None

    monkeypatch.setattr("coldtrail.cli.osint.reverse_ip", fake_reverse)
    monkeypatch.setattr("coldtrail.cli.osint.ptr", fake_ptr)
    monkeypatch.setattr("coldtrail.cli.osint.shodan_host", fake_shodan)
    result = runner.invoke(
        app, ["--db", str(tmp_path / "ip.db"), "ip", "1.2.3.4", "--limit", "2", "--json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["hostnames"] == ["a.example", "b.example"]


def test_case_new_and_add_json(tmp_path):
    db = _seed(tmp_path)
    created = runner.invoke(app, ["--db", str(db), "case", "new", "audit", "--json"])
    assert created.exit_code == 0, created.output
    case = json.loads(created.output)
    assert case["name"] == "audit"
    attached = runner.invoke(app, ["--db", str(db), "case", "add", "audit", "1", "--json"])
    assert attached.exit_code == 0, attached.output
    payload = json.loads(attached.output)
    assert payload["case_id"] == case["id"]
    assert payload["run_id"] == 1
