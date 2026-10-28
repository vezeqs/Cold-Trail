"""Privacy-first regression tests: storage, network, auth, and logs."""

from __future__ import annotations

import asyncio
import json
import stat
from pathlib import Path

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from typer.testing import CliRunner

import coldtrail.http as http_mod
from coldtrail.cli import app
from coldtrail.cli._app import _redact_argv
from coldtrail.config import Settings
from coldtrail.evidence import add_evidence, evidence_path
from coldtrail.http import Fetcher, redact_url
from coldtrail.integrations import TOOLS, ToolError
from coldtrail.store import Store
from coldtrail.utils import sensitive_cache_key
from coldtrail.web import create_app

runner = CliRunner()


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(db_path=tmp_path / "t.db", requests_per_second=0, jitter=0)


@pytest.fixture
def client(settings) -> TestClient:
    return TestClient(create_app(settings))


def test_database_and_sidecars_are_owner_only(settings):
    assert settings.keep_raw is False
    assert settings.avatar_hash is False
    with Store(settings.db_path) as store:
        store.start_run("pivot", "alice")
        store.finish_run(1)
        for suffix in ("", "-wal", "-shm"):
            path = Path(f"{settings.db_path}{suffix}")
            if path.exists():
                assert stat.S_IMODE(path.stat().st_mode) == 0o600, path


def test_evidence_blobs_and_directories_are_owner_only(settings):
    with Store(settings.db_path) as store:
        payload = add_evidence(store, data=b"private", filename="note.txt")
        blob = evidence_path(store, payload["sha256"])
        assert stat.S_IMODE(blob.stat().st_mode) == 0o600
        assert stat.S_IMODE(blob.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(blob.parent.parent.stat().st_mode) == 0o700


def test_cli_exports_are_owner_only(settings, tmp_path):
    with Store(settings.db_path) as store:
        run_id = store.start_run("pivot", "alice")
        store.finish_run(run_id)
    destination = tmp_path / "export.json"
    result = runner.invoke(
        app,
        ["--db", str(settings.db_path), "export", str(run_id), "-o", str(destination)],
    )
    assert result.exit_code == 0, result.output
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_tor_uses_remote_dns(settings, monkeypatch):
    captured: dict[str, object] = {}

    class Dummy:
        async def aclose(self) -> None:
            return None

    def fake_client(**kwargs):
        captured.update(kwargs)
        return Dummy()

    monkeypatch.setattr(http_mod.httpx, "AsyncClient", fake_client)
    settings.tor = True
    fetcher = Fetcher(settings)
    asyncio.run(fetcher.close())
    assert captured["proxy"] == "socks5h://127.0.0.1:9050"


@respx.mock
async def test_raw_retention_is_opt_in(settings):
    respx.get("https://api.example/off").mock(return_value=httpx.Response(200, json={"a": 1}))
    respx.get("https://api.example/on").mock(return_value=httpx.Response(200, json={"b": 2}))
    with Store(settings.db_path) as store:
        async with Fetcher(settings, store=store) as fetcher:
            await fetcher.get_json("https://api.example/off")
        assert store.raw_get("https://api.example/off") is None

        settings.keep_raw = True
        async with Fetcher(settings, store=store) as fetcher:
            await fetcher.get_json("https://api.example/on")
        assert store.raw_get("https://api.example/on")["body"] == b'{"b":2}'


def test_sensitive_cache_keys_hide_the_identifier():
    key = sensitive_cache_key("hibp", "Alice@Example.com")
    assert "alice" not in key.casefold()
    assert "example.com" not in key.casefold()
    assert key == sensitive_cache_key("hibp", " alice@example.com ")


async def test_fetched_content_is_capped(settings):
    fetcher = Fetcher(settings)
    response = httpx.Response(
        200,
        content=b"x" * (http_mod.MAX_BODY + 10),
        headers={"content-type": "text/plain"},
        request=httpx.Request("GET", "https://example.test/large"),
    )
    fetched = fetcher._build(response, "https://example.test/large")
    await fetcher.close()
    assert len(fetched.content) == http_mod.MAX_BODY


@respx.mock
async def test_sensitive_cache_does_not_store_email_in_final_url(settings):
    respx.get("https://api.example/verify").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    key = sensitive_cache_key("verify", "alice@example.com")
    with Store(settings.db_path) as store:
        async with Fetcher(settings, store=store) as fetcher:
            await fetcher.get_json(
                "https://api.example/verify",
                params={"email": "alice@example.com"},
                cache_key=key,
            )
        row = store.conn.execute("SELECT url, final_url FROM http_cache").fetchone()
    assert row["url"] == key
    assert "alice" not in row["final_url"].casefold()
    assert "example.com" not in row["final_url"].casefold()


def test_redact_url_masks_email_and_secret_query_values():
    cleaned = redact_url("https://api.example/v1?email=alice@example.com&api_key=supersecret&x=1")
    assert "alice@example.com" not in cleaned
    assert "supersecret" not in cleaned
    assert "[email]" in cleaned
    assert "[redacted]" in cleaned


def test_login_cookie_is_derived_not_the_raw_token(settings):
    settings.web_token = "sekret"
    client = TestClient(create_app(settings))
    response = client.post("/login", data={"token": "sekret"}, follow_redirects=False)
    assert response.status_code == 303
    cookie = response.cookies.get("coldtrail_token")
    assert cookie
    assert cookie != "sekret"
    assert client.get("/").status_code == 200


def test_logout_clears_the_session_cookie(settings):
    settings.web_token = "sekret"
    client = TestClient(create_app(settings))
    client.post("/login", data={"token": "sekret"}, follow_redirects=False)
    assert client.get("/").status_code == 200
    response = client.get("/logout", follow_redirects=False)
    assert response.status_code == 303
    assert client.get("/", follow_redirects=False).status_code == 303


def test_hsts_only_on_https(settings):
    http_client = TestClient(create_app(settings))
    assert "strict-transport-security" not in http_client.get("/").headers
    https_client = TestClient(create_app(settings), base_url="https://testserver")
    assert "strict-transport-security" in https_client.get("/").headers


def test_privacy_headers_are_set(client):
    response = client.get("/")
    assert "img-src 'self' data:" in response.headers["content-security-policy"]
    assert "https:" not in response.headers["content-security-policy"]
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["permissions-policy"].startswith("geolocation=()")
    assert response.headers["cache-control"] == "no-store"


def test_case_export_filename_is_sanitized(settings):
    with Store(settings.db_path) as store:
        store.create_case('a"b', None)
    client = TestClient(create_app(settings))
    response = client.get("/cases/a%22b/export?format=json")
    assert response.status_code == 200
    assert 'filename="coldtrail-case-a-b.json"' in response.headers["content-disposition"]


def test_web_startup_applies_retention(settings):
    with Store(settings.db_path) as store:
        run_id = store.start_run("pivot", "old")
        store.finish_run(run_id)
        store.conn.execute("UPDATE runs SET started_at = '2000-01-01T00:00:00+00:00'")
        store.conn.commit()
    settings.retention_days = 1
    create_app(settings)
    with Store(settings.db_path) as store:
        assert store.run(run_id) is None


def test_audit_argv_redacts_secrets():
    assert _redact_argv(["serve", "--token", "sekret", "--db", "x.db"]) == [
        "serve",
        "--token",
        "[redacted]",
        "--db",
        "x.db",
    ]
    assert _redact_argv(["--token=sekret", "audit"]) == ["--token=[redacted]", "audit"]
    assert _redact_argv(["--passphrase", "pw", "export", "3"]) == [
        "--passphrase",
        "[redacted]",
        "export",
        "3",
    ]


def test_doctor_offline_reports_privacy_posture(settings):
    result = runner.invoke(app, ["--db", str(settings.db_path), "doctor", "--offline", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["online"] is None
    assert data["privacy"]["telemetry"] == "none"
    assert data["privacy"]["raw_retention"] is False
    assert data["db"]["mode"] == "0o600"


@respx.mock
async def test_medium_rejects_xml_entity_expansion(settings):
    from coldtrail.sources import SOURCES

    evil = (
        '<!DOCTYPE rss [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        "<rss><channel><item><title>&xxe;</title></item></channel></rss>"
    )
    respx.get("https://medium.com/feed/@alice").mock(
        return_value=httpx.Response(200, text=evil, headers={"content-type": "application/rss+xml"})
    )
    async with Fetcher(settings) as fetcher:
        posts = await SOURCES["medium"].posts(fetcher, "alice", 10)
    assert posts == []


@respx.mock
async def test_steam_rejects_xml_entity_expansion(settings):
    from coldtrail.sources import SOURCES

    evil = (
        '<!DOCTYPE profile [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        "<profile><steamID>&xxe;</steamID></profile>"
    )
    respx.get("https://steamcommunity.com/id/alice", params={"xml": "1"}).mock(
        return_value=httpx.Response(200, text=evil, headers={"content-type": "text/xml"})
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["steam"].check(fetcher, "alice")
    assert result.status == "error"
    assert "unparseable" in result.detail


def test_nmap_rejects_xml_entity_expansion():
    evil = (
        '<!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        "<nmaprun><host>&xxe;</host></nmaprun>"
    )
    with pytest.raises(ToolError):
        TOOLS["nmap"].parse(evil, "127.0.0.1", Path("."))
