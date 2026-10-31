"""Breach-exposure audit tests: HIBP metadata + Pwned Passwords k-anonymity."""

from __future__ import annotations

import hashlib

import pytest
import respx
from httpx import Response
from typer.testing import CliRunner

from coldtrail.breach import hibp_breaches, pwned_password, sha1_prefix
from coldtrail.cli import app
from coldtrail.config import Settings
from coldtrail.http import Fetcher, FetchError

runner = CliRunner()

HIBP_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/alice%40example.com"


@pytest.fixture
def settings(tmp_path) -> Settings:
    base = Settings.load()
    base.db_path = tmp_path / "breach.db"
    base.hibp_api_key = "test-key"
    return base


BREACH_PAYLOAD = [
    {
        "Name": "Adobe",
        "Title": "Adobe",
        "BreachDate": "2013-10-04",
        "PwnCount": 152445165,
        "DataClasses": ["Email addresses", "Password hints", "Passwords"],
        "Domain": "adobe.com",
        "IsVerified": True,
        "IsSensitive": False,
    },
    {
        "Name": "LinkedIn",
        "Title": "LinkedIn",
        "BreachDate": "2012-05-05",
        "PwnCount": 164611595,
        "DataClasses": ["Email addresses", "Passwords"],
        "Domain": "linkedin.com",
        "IsVerified": True,
        "IsSensitive": False,
    },
]


async def test_hibp_breaches_parses_metadata(settings):
    with respx.mock:
        route = respx.get(HIBP_URL).mock(return_value=Response(200, json=BREACH_PAYLOAD))
        async with Fetcher(settings) as fetcher:
            result = await hibp_breaches(fetcher, "alice@example.com")
    assert result["status"] == "found"
    assert len(result["breaches"]) == 2
    first = result["breaches"][0]
    assert first["name"] == "Adobe"
    assert first["pwn_count"] == 152445165
    assert "Passwords" in first["data_classes"]
    assert route.called
    assert route.calls[0].request.headers["hibp-api-key"] == "test-key"


async def test_hibp_breaches_none(settings):
    with respx.mock:
        respx.get(HIBP_URL).mock(return_value=Response(404))
        async with Fetcher(settings) as fetcher:
            result = await hibp_breaches(fetcher, "alice@example.com")
    assert result["status"] == "none"
    assert result["breaches"] == []


async def test_hibp_breaches_bad_key(settings):
    with respx.mock:
        respx.get(HIBP_URL).mock(return_value=Response(401))
        async with Fetcher(settings) as fetcher:
            result = await hibp_breaches(fetcher, "alice@example.com")
    assert result["status"] == "blocked"
    assert "API key" in result["detail"]


async def test_hibp_breaches_without_key(settings):
    settings.hibp_api_key = None
    with respx.mock(assert_all_called=False) as mock:
        route = mock.get(HIBP_URL).mock(return_value=Response(200, json=[]))
        async with Fetcher(settings) as fetcher:
            result = await hibp_breaches(fetcher, "alice@example.com")
    assert result["status"] == "blocked"
    assert not route.called  # no request without a key


# -- Pwned Passwords --------------------------------------------------------


def test_sha1_prefix_splits_correctly():
    prefix, suffix = sha1_prefix("hunter2")
    digest = hashlib.sha1(b"hunter2").hexdigest().upper()
    assert prefix == digest[:5] and suffix == digest[5:]
    assert len(prefix) == 5 and len(suffix) == 35


async def test_pwned_password_reports_count(settings):
    password = "hunter2"
    prefix, suffix = sha1_prefix(password)
    padding = "0" * 35 + "A:0"
    body = f"0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n{suffix}:42\r\n{padding}\r\n"
    with respx.mock:
        route = respx.get(f"https://api.pwnedpasswords.com/range/{prefix}").mock(
            return_value=Response(200, text=body)
        )
        async with Fetcher(settings) as fetcher:
            result = await pwned_password(fetcher, password)
    assert result["status"] == "pwned"
    assert result["count"] == 42
    assert "prefix" not in result
    # Privacy: only the 5-char prefix is transmitted; the full hash never is.
    full_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    request_url = str(route.calls[0].request.url)
    assert prefix in request_url
    assert full_hash not in request_url
    assert password not in request_url
    assert route.calls[0].request.headers["add-padding"] == "true"


async def test_pwned_password_clean(settings):
    password = "correct-horse-battery-staple-xyz"
    prefix, _ = sha1_prefix(password)
    body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n0000000000000000000000000000000000A:0\r\n"
    with respx.mock:
        respx.get(f"https://api.pwnedpasswords.com/range/{prefix}").mock(
            return_value=Response(200, text=body)
        )
        async with Fetcher(settings) as fetcher:
            result = await pwned_password(fetcher, password)
    assert result["status"] == "clean"
    assert result["count"] == 0


async def test_pwned_password_http_error(settings):
    password = "whatever"
    prefix, _ = sha1_prefix(password)
    with respx.mock:
        respx.get(f"https://api.pwnedpasswords.com/range/{prefix}").mock(return_value=Response(503))
        async with Fetcher(settings) as fetcher:
            result = await pwned_password(fetcher, password)
    assert result["status"] == "error"


async def test_pwned_password_error_does_not_echo_prefix():
    password = "hunter2"
    prefix, _ = sha1_prefix(password)

    class FakeFetcher:
        async def get_text(self, url, **kwargs):
            raise FetchError(f"request to {url} failed")

    result = await pwned_password(FakeFetcher(), password)
    assert result["status"] == "error"
    assert prefix not in result["detail"]


async def test_pwned_password_hashes_the_cache_key():
    password = "hunter2"
    prefix, suffix = sha1_prefix(password)
    captured = {}

    class FakeFetcher:
        async def get_text(self, url, **kwargs):
            captured["url"] = url
            captured["cache_key"] = kwargs.get("cache_key")
            return 200, f"{suffix}:1"

    result = await pwned_password(FakeFetcher(), password)
    assert result["status"] == "pwned"
    assert prefix in captured["url"]
    assert captured["cache_key"].startswith("pwned:")
    assert prefix not in captured["cache_key"]
    assert password not in captured["cache_key"]


# -- CLI --------------------------------------------------------------------


def test_cli_breach_json(tmp_path, monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "test-key")
    with respx.mock:
        respx.get(HIBP_URL).mock(return_value=Response(200, json=BREACH_PAYLOAD))
        result = runner.invoke(
            app,
            ["--db", str(tmp_path / "t.db"), "breach", "alice@example.com", "--json"],
        )
    assert result.exit_code == 0, result.output
    assert '"Adobe"' in result.output


def test_cli_breach_without_key_exits_2(tmp_path, monkeypatch):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    result = runner.invoke(
        app,
        [
            "--db",
            str(tmp_path / "t.db"),
            "--config",
            str(tmp_path / "missing.toml"),
            "breach",
            "alice@example.com",
        ],
    )
    assert result.exit_code == 2
    assert "HIBP_API_KEY" in result.output


def test_cli_pwned_env_reports_exposure(tmp_path, monkeypatch):
    password = "hunter2"
    prefix, suffix = sha1_prefix(password)
    monkeypatch.setenv("LH_TEST_PW", password)
    with respx.mock:
        respx.get(f"https://api.pwnedpasswords.com/range/{prefix}").mock(
            return_value=Response(200, text=f"{suffix}:7\r\n")
        )
        result = runner.invoke(
            app,
            [
                "--db",
                str(tmp_path / "t.db"),
                "pwned",
                "--password-env",
                "LH_TEST_PW",
                "--json",
            ],
        )
    assert result.exit_code == 1
    assert '"count": 7' in result.output


def test_cli_pwned_clean_exits_0(tmp_path, monkeypatch):
    password = "a-very-unique-test-password-9f8e7d"
    prefix, _ = sha1_prefix(password)
    monkeypatch.setenv("LH_TEST_PW", password)
    with respx.mock:
        respx.get(f"https://api.pwnedpasswords.com/range/{prefix}").mock(
            return_value=Response(200, text="0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n")
        )
        result = runner.invoke(
            app,
            ["--db", str(tmp_path / "t.db"), "pwned", "--password-env", "LH_TEST_PW"],
        )
    assert result.exit_code == 0
    assert "clean" in result.output
