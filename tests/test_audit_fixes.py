"""Regression tests for the 2026-10-30 audit (see AUDIT.md)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import stat
import xml.etree.ElementTree as ET
from pathlib import Path

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from typer.testing import CliRunner

import coldtrail.cli.collect as collect_mod
import coldtrail.watch as watch_mod
from coldtrail.analysis import extract_entities
from coldtrail.cli import app
from coldtrail.config import Settings
from coldtrail.evidence import add_evidence, evidence_path, verify_evidence
from coldtrail.http import BlockedError, Fetcher
from coldtrail.models import CheckResult, PivotReport, Post, Profile
from coldtrail.report import to_dot, to_gexf, to_graphml, to_html, to_markdown
from coldtrail.store import Store
from coldtrail.web import create_app

runner = CliRunner()


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(db_path=tmp_path / "t.db", requests_per_second=0, jitter=0)


# -- F1: health endpoint must not leak exception text -----------------------


def test_health_does_not_leak_exception_text(tmp_path):
    broken = tmp_path / "not-a-database"
    broken.mkdir()
    client = TestClient(create_app(Settings(db_path=broken)))
    response = client.get("/healthz")
    assert response.status_code == 503
    assert response.json()["detail"] == "database unavailable"
    assert str(broken) not in response.text


# -- F2: XML exports must stay well-formed ----------------------------------


def test_graphml_and_gexf_escape_quotes_and_controls():
    profile = {
        "source": "x",
        "username": 'a"b',
        "url": "https://example.test/a",
        "display_name": 'n"m\x00',
    }
    graphml = to_graphml({"profiles": [profile]})
    gexf = to_gexf({"profiles": [profile]})
    ET.fromstring(graphml)
    ET.fromstring(gexf)
    assert 'a"b' in graphml
    assert 'n"m' in graphml


# -- F3: blocked pages must not be replayed from cache ----------------------


@respx.mock
async def test_blocked_pages_are_not_cached(settings):
    route = respx.get("https://api.example/wall").mock(
        return_value=httpx.Response(
            200,
            text="<html><title>Just a moment...</title></html>",
            headers={"content-type": "text/html"},
        )
    )
    with Store(settings.db_path) as store:
        async with Fetcher(settings, store=store) as fetcher:
            with pytest.raises(BlockedError):
                await fetcher.get_text("https://api.example/wall")
            with pytest.raises(BlockedError):
                await fetcher.get_text("https://api.example/wall")
    assert route.call_count == 2


# -- F4: database file is private from creation ----------------------------


def test_store_creates_private_database_and_parent(tmp_path):
    db = tmp_path / "private" / "nested" / "t.db"
    with Store(db):
        pass
    assert stat.S_IMODE(db.stat().st_mode) == 0o600
    assert stat.S_IMODE(db.parent.stat().st_mode) == 0o700


# -- F5: blank targets are rejected ----------------------------------------


def test_pivot_rejects_blank_target(settings):
    result = runner.invoke(app, ["--db", str(settings.db_path), "pivot", " "])
    assert result.exit_code != 0
    assert "non-empty" in result.output


def test_harvest_rejects_blank_username(settings):
    result = runner.invoke(app, ["--db", str(settings.db_path), "harvest", " ", "-s", "github"])
    assert result.exit_code != 0
    assert "non-empty" in result.output


def test_web_pivot_rejects_blank_target(settings):
    client = TestClient(create_app(settings))
    assert client.post("/pivot", data={"target": " "}).status_code == 400
    assert client.post("/api/pivot", json={"target": " "}).status_code == 400


def test_web_tools_allow_targetless_recluster(settings):
    client = TestClient(create_app(settings))
    response = client.post("/tools/run", data={"tool": "recluster"})
    assert response.status_code == 200


# -- F6/F7: cache varies by Accept and keeps the stored charset ------------


@respx.mock
async def test_cache_varies_by_accept(settings):
    route = respx.get("https://api.example/dual").mock(
        side_effect=[
            httpx.Response(200, text="<html>hi</html>", headers={"content-type": "text/html"}),
            httpx.Response(200, json={"ok": True}),
        ]
    )
    with Store(settings.db_path) as store:
        async with Fetcher(settings, store=store) as fetcher:
            _, text = await fetcher.get_text("https://api.example/dual")
            _, data = await fetcher.get_json("https://api.example/dual")
    assert text == "<html>hi</html>"
    assert data == {"ok": True}
    assert route.call_count == 2


@respx.mock
async def test_cached_body_uses_stored_charset(settings):
    body = "café".encode("iso-8859-1")
    route = respx.get("https://api.example/latin").mock(
        return_value=httpx.Response(
            200, content=body, headers={"content-type": "text/html; charset=iso-8859-1"}
        )
    )
    with Store(settings.db_path) as store:
        async with Fetcher(settings, store=store) as fetcher:
            first = await fetcher.get_text("https://api.example/latin")
            second = await fetcher.get_text("https://api.example/latin")
    assert first[1] == "café"
    assert second[1] == "café"
    assert route.call_count == 1


# -- F8: reports order posts chronologically -------------------------------


def test_html_report_orders_posts_chronologically():
    payload = {
        "run": {"id": 1, "target": "alice"},
        "posts": [
            {
                "created_at": "2024-01-01T10:00:00+14:00",
                "source": "s",
                "username": "u",
                "text": "FIRST_UTC",
                "url": "",
            },
            {
                "created_at": "2024-01-01T09:00:00-12:00",
                "source": "s",
                "username": "u",
                "text": "SECOND_UTC",
                "url": "",
            },
        ],
    }
    html = to_html(payload)
    assert html.index("FIRST_UTC") < html.index("SECOND_UTC")


def test_markdown_tables_escape_pipes_and_newlines():
    payload = {
        "run": {"target": "alice"},
        "profiles": [
            {
                "source": "s",
                "username": "u",
                "display_name": "a|b\nc",
                "url": "",
            }
        ],
    }
    text = to_markdown(payload)
    assert "a\\|b c" in text


def test_dot_export_handles_missing_score():
    text = to_dot(
        {
            "profiles": [{"source": "a", "username": "u"}],
            "links": [
                {
                    "source_a": "a",
                    "username_a": "u",
                    "source_b": "b",
                    "username_b": "v",
                }
            ],
        }
    )
    assert "weight=0.0" in text


# -- F9: harvest/watch windows use real chronology -------------------------


def _mixed_offset_posts() -> list[Post]:
    return [
        Post(
            source="github",
            username="alice",
            post_id="p-late",
            url="https://example.test/2",
            created_at="2024-01-01T09:00:00-12:00",
            text="late",
        ),
        Post(
            source="github",
            username="alice",
            post_id="p-early",
            url="https://example.test/1",
            created_at="2024-01-01T10:00:00+14:00",
            text="early",
        ),
    ]


def test_harvest_window_uses_chronological_order(settings, monkeypatch):
    profile = Profile(source="github", username="alice", url="https://github.com/alice")
    posts = _mixed_offset_posts()

    async def fake_harvest(*args, **kwargs):
        return CheckResult("github", "alice", "found", profile=profile), posts

    monkeypatch.setattr(collect_mod, "run_harvest", fake_harvest)
    captured: dict[str, object] = {}

    def fake_mark(self, source, username, seen, run_id, *, since=None):
        captured["since"] = since
        return 0

    def fake_cursor(self, source, username, cursor, last_seen_at):
        captured["cursor"] = (cursor, last_seen_at)

    monkeypatch.setattr(Store, "mark_missing_posts", fake_mark)
    monkeypatch.setattr(Store, "set_cursor", fake_cursor)

    result = runner.invoke(app, ["--db", str(settings.db_path), "harvest", "alice", "-s", "github"])
    assert result.exit_code == 0, result.output
    assert captured["since"] == "2024-01-01T10:00:00+14:00"
    assert captured["cursor"] == ("p-late", "2024-01-01T09:00:00-12:00")


def test_watch_window_uses_chronological_order(settings, monkeypatch):
    profile = Profile(source="github", username="alice", url="https://github.com/alice")
    check = CheckResult("github", "alice", "found", profile=profile)
    posts = _mixed_offset_posts()

    async def fake_pivot(*args, **kwargs):
        return PivotReport(target="alice", kind="username", results=[check], links=[])

    async def fake_harvest(*args, **kwargs):
        return check, posts

    monkeypatch.setattr(watch_mod, "pivot", fake_pivot)
    monkeypatch.setattr(watch_mod, "harvest", fake_harvest)
    captured: dict[str, object] = {}

    def fake_mark(self, source, username, seen, run_id, *, since=None):
        captured["since"] = since
        return 0

    monkeypatch.setattr(Store, "mark_missing_posts", fake_mark)

    with Store(settings.db_path) as store:
        cycles = asyncio.run(
            watch_mod.watch(
                "alice",
                settings=settings,
                store=store,
                interval=0,
                iterations=1,
                alerters=[],
            )
        )
    assert cycles == 1
    assert captured["since"] == "2024-01-01T10:00:00+14:00"


# -- F10/F11: evidence integrity and path safety ---------------------------


def test_evidence_hashes_the_bytes_it_reads(settings, monkeypatch, tmp_path):
    source = tmp_path / "evidence.bin"
    source.write_bytes(b"on-disk")
    monkeypatch.setattr(Path, "read_bytes", lambda self: b"read-once")
    with Store(settings.db_path) as store:
        payload = add_evidence(store, source_path=source)
        assert payload["sha256"] == hashlib.sha256(b"read-once").hexdigest()
        with open(evidence_path(store, payload["sha256"]), "rb") as handle:
            assert handle.read() == b"read-once"


def test_evidence_path_rejects_invalid_digest(settings):
    with Store(settings.db_path) as store:
        with pytest.raises(ValueError):
            evidence_path(store, "../../etc/passwd")
        store.add_attachment(
            run_id=None,
            target_type="run",
            target=None,
            sha256="../../etc/passwd",
            filename="x",
            media_type="text/plain",
            size=0,
            note=None,
        )
        problems = verify_evidence(store)
    assert problems
    assert problems[0]["problem"] == "invalid digest"


# -- F12: doctor redacts proxy credentials --------------------------------


def test_doctor_redacts_proxy_credentials(settings):
    result = runner.invoke(
        app,
        [
            "--db",
            str(settings.db_path),
            "--proxy",
            "http://user:s3cret@127.0.0.1:8080",
            "doctor",
            "--offline",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "s3cret" not in result.output
    assert "[redacted]" in result.output
    with Store(settings.db_path) as store:
        assert "s3cret" not in json.dumps(store.audit())


def test_doctor_warns_about_world_readable_config(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text("", encoding="utf-8")
    config.chmod(0o644)
    result = runner.invoke(
        app,
        [
            "--config",
            str(config),
            "--db",
            str(tmp_path / "t.db"),
            "doctor",
            "--offline",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["privacy"]["config_mode_warning"] is True


# -- F13: redirects cannot reach loopback ----------------------------------


@respx.mock
async def test_redirect_to_loopback_is_blocked(settings):
    respx.get("https://public.example/start").mock(
        return_value=httpx.Response(302, headers={"location": "http://127.0.0.1/secret"})
    )
    respx.get("http://127.0.0.1/secret").mock(return_value=httpx.Response(200, text="secret"))
    async with Fetcher(settings) as fetcher:
        with pytest.raises(BlockedError, match="non-public"):
            await fetcher.get_text("https://public.example/start")


# -- F14: Matrix IDs are not Telegram handles ------------------------------


def test_matrix_ids_are_not_telegram_handles():
    kinds = {entity.kind for entity in extract_entities("@alice:matrix.org", "s", "u")}
    assert "matrix" in kinds
    assert "telegram" not in kinds


# -- F15: search errors are not reflected ----------------------------------


def test_search_page_does_not_reflect_exception_text(settings, monkeypatch):
    client = TestClient(create_app(settings))

    def boom(self, *args, **kwargs):
        raise RuntimeError("secret sql detail")

    monkeypatch.setattr("coldtrail.web.app.Store.search", boom)
    response = client.get("/search", params={"q": "alice"})
    assert response.status_code == 200
    assert "secret sql detail" not in response.text
    assert "invalid query" in response.text


# -- F16: corrupt JSON rows and audit failures do not crash ----------------


def test_cli_survives_audit_log_failure(settings, monkeypatch):
    import sqlite3

    import coldtrail.cli._app as app_mod

    def boom(self, *args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(app_mod.Store, "audit_log", boom)
    result = runner.invoke(app, ["--db", str(settings.db_path), "db"])
    assert result.exit_code == 0, result.output


def test_corrupt_json_rows_do_not_crash_queries(settings):
    with Store(settings.db_path) as store:
        run_id = store.start_run("pivot", "alice")
        store.conn.execute(
            """INSERT INTO profiles (run_id, source, username, url, extra_json)
               VALUES (?, ?, ?, ?, ?)""",
            (run_id, "github", "alice", "https://example.test/alice", "{not json"),
        )
        store.conn.commit()
        rows = store.profiles(run_id=run_id)
    assert rows[0]["extra"] == {}


# -- F17: case names reject whitespace -------------------------------------


def test_case_names_reject_whitespace(settings):
    with Store(settings.db_path) as store, pytest.raises(ValueError):
        store.create_case("   ")
    client = TestClient(create_app(settings))
    assert client.post("/cases/new", data={"name": "   "}).status_code == 400
