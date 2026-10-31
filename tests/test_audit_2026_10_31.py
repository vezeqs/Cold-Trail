"""Regression tests for the 2026-10-31 audit findings.

Every test here failed before its fix; each one names the finding it guards.
"""

from __future__ import annotations

import asyncio
import socket
import sys
import time
from datetime import UTC
from pathlib import Path

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from coldtrail.analysis import infer_timezone
from coldtrail.cli import app
from coldtrail.config import ConfigError, Settings
from coldtrail.domain import check_subdomain_takeover, crtsh, guess_mx_provider, tls_cert_info
from coldtrail.evidence import add_evidence, evidence_path, verify_evidence
from coldtrail.http import BlockedError, Fetcher
from coldtrail.models import Post
from coldtrail.report import to_csv, to_maltego_csv
from coldtrail.security import is_public_host, resolve_public_ips
from coldtrail.store import Store
from coldtrail.store.base import StoreError
from coldtrail.utils import redact_url_credentials, write_private
from coldtrail.web.app import create_app
from coldtrail.web.helpers import COOKIE_NAME, _cookie_value

runner = CliRunner()


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(db_path=tmp_path / "audit.db", cache_ttl=0, requests_per_second=0)


# -- finding 1: Host / Origin validation ------------------------------------


def test_web_rejects_foreign_host_header(settings):
    client = TestClient(create_app(settings))
    response = client.get("/api/runs", headers={"Host": "attacker.example:8765"})
    assert response.status_code == 403


def test_web_rejects_cross_origin_post(settings):
    client = TestClient(create_app(settings))
    response = client.post(
        "/tools/run",
        data={"tool": "dorks", "target": "example.com"},
        headers={"Origin": "https://evil.example"},
    )
    assert response.status_code == 403


def test_web_rejects_cross_site_fetch_metadata(settings):
    client = TestClient(create_app(settings))
    response = client.post(
        "/tools/run",
        data={"tool": "dorks", "target": "example.com"},
        headers={"Sec-Fetch-Site": "cross-site"},
    )
    assert response.status_code == 403


def test_web_allows_browser_form_post_with_null_origin(settings):
    # Chrome sends `Origin: null` for form posts under `Referrer-Policy: no-referrer`.
    client = TestClient(create_app(settings))
    response = client.post(
        "/tools/run",
        data={"tool": "dorks", "target": "example.com"},
        headers={"Origin": "null", "Sec-Fetch-Site": "same-origin"},
    )
    assert response.status_code == 200


def test_web_rejects_sandboxed_null_origin_cross_site(settings):
    client = TestClient(create_app(settings))
    response = client.post(
        "/tools/run",
        data={"tool": "dorks", "target": "example.com"},
        headers={"Origin": "null", "Sec-Fetch-Site": "cross-site"},
    )
    assert response.status_code == 403


def test_web_allows_same_origin_and_loopback(settings):
    client = TestClient(create_app(settings))
    same_origin = client.post(
        "/tools/run",
        data={"tool": "dorks", "target": "example.com"},
        headers={"Origin": "http://testserver"},
    )
    assert same_origin.status_code == 200
    loopback = client.get("/api/runs", headers={"Host": "127.0.0.1:8765"})
    assert loopback.status_code == 200


def test_web_allows_remote_host_when_explicitly_configured(tmp_path):
    settings = Settings(db_path=tmp_path / "remote.db", cache_ttl=0)
    settings.allow_remote_host = True
    client = TestClient(create_app(settings))
    assert client.get("/api/runs", headers={"Host": "coldtrail.lan:8765"}).status_code == 200


# -- finding 18 (review): the cookie is a bearer credential -----------------


def test_login_cookie_is_expiring_and_not_the_token(settings):
    settings.web_token = "sekret"
    client = TestClient(create_app(settings))
    response = client.post("/login", data={"token": "sekret"}, follow_redirects=False)
    cookie = response.cookies.get(COOKIE_NAME)
    assert cookie and cookie != "sekret"
    issued, _, signature = cookie.partition(".")
    assert issued.isdigit() and signature
    assert client.get("/").status_code == 200


def test_expired_cookie_is_rejected(settings):
    settings.web_token = "sekret"
    client = TestClient(create_app(settings))
    stale = _cookie_value("sekret", int(time.time()) - 90_000)
    client.cookies.set(COOKIE_NAME, stale)
    assert client.get("/", follow_redirects=False).status_code == 303


def test_tampered_cookie_is_rejected(settings):
    settings.web_token = "sekret"
    client = TestClient(create_app(settings))
    client.cookies.set(COOKIE_NAME, f"{int(time.time())}.deadbeef")
    assert client.get("/", follow_redirects=False).status_code == 303


# -- finding 2 / 16: TLS probe and DNS pinning ------------------------------


def test_tls_probe_is_disabled_under_proxy(monkeypatch):
    attempts = []

    async def fake_open(*args, **kwargs):
        attempts.append(args)
        raise AssertionError("must not connect directly")

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    settings = Settings(proxy="socks5h://127.0.0.1:9050")
    assert asyncio.run(tls_cert_info("example.com", settings=settings)) is None
    assert attempts == []


def test_tls_probe_connects_to_the_validated_ip(monkeypatch):
    captured = {}

    class FakeWriter:
        def get_extra_info(self, name):
            return None

        def close(self):
            return None

        async def wait_closed(self):
            return None

    async def fake_open(host, port, **kwargs):
        captured["host"] = host
        captured["port"] = port
        captured["sni"] = kwargs.get("server_hostname")
        return object(), FakeWriter()

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    monkeypatch.setattr(
        "coldtrail.security.socket.getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))],
    )
    asyncio.run(tls_cert_info("example.com"))
    assert captured["host"] == "93.184.216.34"
    assert captured["sni"] == "example.com"


def test_tls_probe_refuses_private_resolution(monkeypatch):
    async def fake_open(*args, **kwargs):
        raise AssertionError("must not connect to a private address")

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    monkeypatch.setattr(
        "coldtrail.security.socket.getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    assert asyncio.run(tls_cert_info("rebind.example")) is None


def test_resolve_public_ips_rejects_private_answers():
    with pytest.raises(ValueError, match="non-public"):
        resolve_public_ips("localhost")


def test_pinned_transport_rewrites_the_url_but_keeps_host_and_sni(monkeypatch):
    from coldtrail.http import _PinnedTransport

    monkeypatch.setattr(
        "coldtrail.security.socket.getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))],
    )
    transport = _PinnedTransport()
    request = httpx.Request("GET", "https://example.com/path?q=1")
    transport._pin(request)
    assert request.url.host == "93.184.216.34"
    assert request.url.path == "/path"
    assert request.headers["host"] == "example.com"
    assert request.extensions["sni_hostname"] == "example.com"


def test_pinned_transport_refuses_a_private_answer(monkeypatch):
    from coldtrail.http import _PinnedTransport

    monkeypatch.setattr(
        "coldtrail.security.socket.getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0))],
    )
    transport = _PinnedTransport()
    request = httpx.Request("GET", "https://rebind.example/")
    with pytest.raises(httpx.ConnectError, match="non-public"):
        transport._pin(request)


def test_redirect_to_a_hostname_that_resolves_private_is_blocked(settings):
    async def run():
        async with Fetcher(settings) as fetcher:
            return await fetcher.get("https://public.example/start")

    def fake_getaddrinfo(host, *args, **kwargs):
        address = "10.1.2.3" if host == "internal.example" else "93.184.216.34"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0))]

    with respx.mock:
        respx.get("https://public.example/start").mock(
            return_value=httpx.Response(302, headers={"Location": "http://internal.example/x"})
        )
        respx.get("http://internal.example/x").mock(return_value=httpx.Response(200, text="ok"))
        original = socket.getaddrinfo
        socket.getaddrinfo = fake_getaddrinfo
        try:
            with pytest.raises(BlockedError, match="non-public"):
                asyncio.run(run())
        finally:
            socket.getaddrinfo = original


# -- finding 8: Retry-After is capped ---------------------------------------


def test_retry_after_is_capped(settings):
    sleeps = []

    async def fake_sleep(delay, *args, **kwargs):
        sleeps.append(delay)

    with respx.mock:
        respx.get("https://example.com/x").mock(
            return_value=httpx.Response(429, headers={"Retry-After": "7200"})
        )
        original = asyncio.sleep
        asyncio.sleep = fake_sleep
        try:

            async def run():
                async with Fetcher(settings) as fetcher:
                    await fetcher.get("https://example.com/x")

            with pytest.raises(BlockedError, match="Retry-After"):
                asyncio.run(run())
        finally:
            asyncio.sleep = original
    assert sleeps == []


def test_small_retry_after_is_honoured(settings):
    sleeps = []

    async def fake_sleep(delay, *args, **kwargs):
        sleeps.append(delay)

    with respx.mock:
        respx.get("https://example.com/x").mock(
            return_value=httpx.Response(429, headers={"Retry-After": "1"})
        )
        original = asyncio.sleep
        asyncio.sleep = fake_sleep
        try:

            async def run():
                async with Fetcher(settings) as fetcher:
                    await fetcher.get("https://example.com/x")

            with pytest.raises(BlockedError):
                asyncio.run(run())
        finally:
            asyncio.sleep = original
    assert sleeps and all(delay <= 10 for delay in sleeps)


# -- finding 17 (review): robots.txt redirect --------------------------------


def test_robots_redirect_to_private_host_is_ignored(settings):
    settings = Settings(
        db_path=settings.db_path,
        cache_ttl=0,
        requests_per_second=0,
        respect_robots=True,
    )
    with respx.mock:
        respx.get("https://public.example/robots.txt").mock(
            return_value=httpx.Response(302, headers={"Location": "http://127.0.0.1/robots.txt"})
        )
        respx.get("http://127.0.0.1/robots.txt").mock(
            return_value=httpx.Response(200, text="User-agent: *\nDisallow: /\n")
        )
        respx.get("https://public.example/alice").mock(return_value=httpx.Response(200, text="hi"))

        async def run():
            async with Fetcher(settings) as fetcher:
                return await fetcher.get("https://public.example/alice")

        response = asyncio.run(run())
    assert response.status == 200


# -- finding 19 (review): CGNAT and friends ---------------------------------


@pytest.mark.parametrize(
    "address", ["100.64.0.1", "100.127.255.254", "192.0.0.1", "198.18.0.1", "240.0.0.1"]
)
def test_non_public_ranges_are_blocked(address):
    assert is_public_host(address) is False


# -- finding 4: CSV formula injection ---------------------------------------


def test_csv_formula_injection_is_neutralised():
    payload = {
        "profiles": [
            {
                "username": '=HYPERLINK("http://evil.example/x","click")',
                "source": "github",
                "bio": "@SUM(1+1)",
                "url": "+cmd|' /C calc'!A0",
            }
        ]
    }
    csv_text = to_csv(payload)
    assert "\"'=HYPERLINK" in csv_text
    assert "'@SUM" in csv_text
    assert "'+cmd" in csv_text


def test_maltego_csv_formula_injection_is_neutralised():
    payload = {
        "entities": [
            {
                "source": "github",
                "username": "alice",
                "kind": "email",
                "value": "=cmd|' /C calc'!A0",
            }
        ]
    }
    assert "'=cmd" in to_maltego_csv(payload)


# -- finding 5: malformed environment ---------------------------------------


def test_bad_env_timeout_is_a_config_error(monkeypatch, tmp_path):
    monkeypatch.setenv("COLDTRAIL_TIMEOUT", "abc")
    with pytest.raises(ConfigError, match="COLDTRAIL_TIMEOUT"):
        Settings.load(tmp_path / "missing.toml")


def test_bad_env_cache_ttl_is_a_config_error(monkeypatch, tmp_path):
    monkeypatch.setenv("COLDTRAIL_CACHE_TTL", "1.5")
    with pytest.raises(ConfigError, match="COLDTRAIL_CACHE_TTL"):
        Settings.load(tmp_path / "missing.toml")


def test_cli_reports_bad_env_without_a_traceback(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("COLDTRAIL_TIMEOUT", "abc")
    monkeypatch.setattr(
        sys, "argv", ["coldtrail", "--db", str(tmp_path / "x.db"), "doctor", "--offline"]
    )
    from coldtrail.cli import main as cli_main

    with pytest.raises(SystemExit) as excinfo:
        cli_main()
    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    output = captured.err + captured.out
    assert "COLDTRAIL_TIMEOUT" in output
    assert "Traceback" not in output


# -- finding 6: corrupt database --------------------------------------------


def test_corrupt_database_raises_store_error(tmp_path):
    bad = tmp_path / "bad.db"
    bad.write_bytes(b"this is not a database")
    with pytest.raises(StoreError, match="not a database"):
        Store(bad)


def test_cli_reports_corrupt_database_without_a_traceback(tmp_path, capsys):
    bad = tmp_path / "bad.db"
    bad.write_bytes(b"this is not a database")
    monkeypatch_argv = ["coldtrail", "--db", str(bad), "doctor", "--offline"]
    original = sys.argv
    sys.argv = monkeypatch_argv
    from coldtrail.cli import main as cli_main

    try:
        with pytest.raises(SystemExit) as excinfo:
            cli_main()
    finally:
        sys.argv = original
    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err + captured.out
    assert str(bad) in captured.err + captured.out


# -- finding 7: malformed proxy URL -----------------------------------------


def test_redact_url_credentials_survives_a_bad_port():
    assert redact_url_credentials("http://user:pass@example.com:notaport") == "[invalid url]"
    assert redact_url_credentials("http://user:pass@[::1") == "[invalid url]"
    assert redact_url_credentials("http://user:pass@example.com:8080") == (
        "http://[redacted]@example.com:8080"
    )


def test_config_json_survives_a_bad_proxy(monkeypatch, tmp_path):
    monkeypatch.setenv("COLDTRAIL_PROXY", "http://user:pass@example.com:notaport")
    result = runner.invoke(
        app,
        ["--db", str(tmp_path / "p.db"), "--config", str(tmp_path / "n.toml"), "config", "--json"],
    )
    assert result.exit_code == 0, result.output
    assert "[invalid url]" in result.output


def test_fetcher_rejects_a_bad_proxy_with_a_clean_error():
    with pytest.raises(ConfigError, match="proxy"):
        Fetcher(Settings(proxy="http://user:pass@example.com:notaport"))


# -- finding 10: config validation ------------------------------------------


def test_config_rejects_unknown_keys(tmp_path):
    path = tmp_path / "c.toml"
    path.write_text("timeout = 5\ntimeoutt = 10\n")
    with pytest.raises(ConfigError, match="timeoutt"):
        Settings.load(path)


def test_config_rejects_a_section_table(tmp_path):
    path = tmp_path / "c.toml"
    path.write_text("[settings]\ntimeout = 5\n")
    with pytest.raises(ConfigError, match="settings"):
        Settings.load(path)


def test_config_rejects_a_wrong_type(tmp_path):
    path = tmp_path / "c.toml"
    path.write_text('timeout = "abc"\n')
    with pytest.raises(ConfigError, match="timeout"):
        Settings.load(path)


def test_config_accepts_valid_values(tmp_path):
    path = tmp_path / "c.toml"
    path.write_text("timeout = 3\nconcurrency = 8\ntor = true\n")
    loaded = Settings.load(path)
    assert loaded.timeout == 3.0
    assert loaded.concurrency == 8
    assert loaded.tor is True


def test_allow_remote_host_env_is_honoured(monkeypatch, tmp_path):
    # A reverse proxy keeps the bind loopback but forwards the external Host;
    # the documented opt-in must survive the config/env path.
    monkeypatch.setenv("COLDTRAIL_ALLOW_REMOTE_HOST", "1")
    settings = Settings.load(tmp_path / "missing.toml")
    assert settings.allow_remote_host is True


# -- finding 11: export permissions -----------------------------------------


def test_write_private_is_0600_from_creation(tmp_path):
    import os

    path = tmp_path / "export.json"
    original = os.umask(0o022)
    try:
        write_private(path, b"{}")
    finally:
        os.umask(original)
    assert path.stat().st_mode & 0o777 == 0o600


def test_write_private_tightens_an_existing_file(tmp_path):
    path = tmp_path / "export.json"
    path.write_bytes(b"old")
    path.chmod(0o644)
    write_private(path, b"new")
    assert path.stat().st_mode & 0o777 == 0o600


# -- finding 12: timezone inference -----------------------------------------


def test_timezone_inference_is_stable_across_offsets():
    from datetime import datetime, timedelta, timezone

    local = [
        Post(
            source="x",
            username="u",
            post_id=str(i),
            url="http://x",
            created_at=f"2024-01-01T{hour:02d}:00:00-05:00",
        )
        for i, hour in enumerate(range(9, 24))
    ]
    utc = [
        Post(
            source="x",
            username="u",
            post_id=str(i),
            url="http://x",
            created_at=datetime(2024, 1, 1, hour, tzinfo=timezone(timedelta(hours=-5)))
            .astimezone(UTC)
            .isoformat(),
        )
        for i, hour in enumerate(range(9, 24))
    ]
    assert infer_timezone(local) == infer_timezone(utc)


# -- finding 13: corrupt audit row ------------------------------------------


def test_corrupt_audit_args_do_not_crash_the_query(settings):
    with Store(settings.db_path) as store:
        store.conn.execute(
            "INSERT INTO audit (at, command, target, args_json) VALUES (?, ?, ?, ?)",
            ("2024-01-01T00:00:00+00:00", "pivot", "x", "{not json"),
        )
        store.conn.commit()
        rows = store.audit()
    assert rows and rows[0]["args"] == {}


# -- finding 14: silent empties ---------------------------------------------


def _seeded_db(path: Path) -> None:
    from coldtrail.models import CheckResult, Profile

    with Store(path) as store:
        run_id = store.start_run("pivot", "alice")
        store.save_checks(run_id, [CheckResult("github", "alice", "found")])
        store.save_profiles(
            run_id,
            [Profile(source="github", username="alice", url="https://github.com/alice", extra={})],
        )
        store.save_posts(
            run_id,
            [
                Post(
                    source="github",
                    username="alice",
                    post_id="1",
                    url="http://x/1",
                    created_at="2024-01-01T10:00:00Z",
                    text="hello",
                )
            ],
        )
        store.finish_run(run_id)


def test_timeline_rejects_an_unparseable_since(tmp_path):
    db = tmp_path / "t.db"
    _seeded_db(db)
    result = runner.invoke(app, ["--db", str(db), "timeline", "--since", "yesterday"])
    assert result.exit_code == 2
    assert "ISO" in result.output


def test_export_rejects_an_unknown_table(tmp_path):
    db = tmp_path / "t.db"
    _seeded_db(db)
    result = runner.invoke(
        app, ["--db", str(db), "export", "1", "--format", "csv", "--table", "nope"]
    )
    assert result.exit_code == 2
    assert "nope" in result.output


# -- finding 9: domain suffix matching --------------------------------------


class _FakeJsonFetcher:
    def __init__(self, payload):
        self.payload = payload

    async def get_json(self, url, *, params=None, **kwargs):
        return 200, self.payload


def test_crtsh_ignores_suffix_lookalikes():
    fetcher = _FakeJsonFetcher([{"name_value": "www.example.com\nnotexample.com\nexample.com"}])
    assert asyncio.run(crtsh(fetcher, "example.com")) == ["example.com", "www.example.com"]


def test_mx_provider_requires_a_label_boundary():
    assert guess_mx_provider(["mail.notgoogle.com"]) is None
    assert guess_mx_provider(["mail.google.com"]) == "Google Workspace"


def test_takeover_requires_a_label_boundary(monkeypatch):
    async def fail_get_text(*args, **kwargs):
        raise AssertionError("must not probe a lookalike CNAME")

    monkeypatch.setattr(Fetcher, "get_text", fail_get_text, raising=False)
    fetcher = object()
    result = asyncio.run(check_subdomain_takeover(fetcher, "example.com", ["notherokuapp.com"]))
    assert result is None


# -- findings 20/21 (review): evidence scale --------------------------------


def test_add_evidence_streams_from_a_path(settings, tmp_path, monkeypatch):
    source = tmp_path / "big.bin"
    source.write_bytes(b"x" * (2 * 1024 * 1024))
    expected = source.open("rb").read()

    def explode(self):
        raise AssertionError("add_evidence must stream, not read the whole file")

    monkeypatch.setattr(Path, "read_bytes", explode)
    with Store(settings.db_path) as store:
        row = add_evidence(store, source_path=source, filename="big.bin")
        blob = evidence_path(store, row["sha256"]).open("rb").read()
    assert blob == expected
    assert row["size"] == 2 * 1024 * 1024


def test_verify_evidence_pages_through_attachments(settings):
    with Store(settings.db_path) as store:
        rows = [
            add_evidence(store, data=f"blob-{i}".encode(), filename=f"b{i}.bin") for i in range(3)
        ]
        evidence_path(store, rows[0]["sha256"]).unlink()
        evidence_path(store, rows[1]["sha256"]).write_bytes(b"tampered")
        problems = verify_evidence(store, page_size=1)
    assert {problem["id"] for problem in problems} == {rows[0]["id"], rows[1]["id"]}
