from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx

import larpharvester
from larpharvester.config import Settings
from larpharvester.http import Fetcher
from larpharvester.sites import SiteDef, load_sites, slugify
from larpharvester.sources.declarative import DeclarativeSource, parse_meta

DATA = Path(larpharvester.__file__).parent / "data" / "sites.toml"


def make_site(**kwargs) -> SiteDef:
    defaults = {"name": "Test", "url": "https://t.example/{username}"}
    return SiteDef(**{**defaults, **kwargs})


def test_corpus_loads():
    sites = load_sites(DATA)
    assert len(sites) > 400
    assert any(site.name == "GitHub" for site in sites)
    assert all("{username}" in site.url or site.url_probe for site in sites)


def test_slugify():
    assert slugify("About.me") == "about-me"
    assert slugify("1337x") == "1337x"
    assert slugify("!!!") == "site"


def test_parse_meta_prefers_og_tags():
    meta = parse_meta(
        "<html><head><title>fallback</title>"
        '<meta property="og:title" content="OG">'
        '<meta name="description" content="desc">'
        '<meta property="og:image" content="https://x/i.png"></head></html>'
    )
    assert meta.title == "OG"
    assert meta.description == "desc"
    assert meta.image == "https://x/i.png"


@pytest.fixture
def settings(tmp_path):
    return Settings(db_path=tmp_path / "t.db")


@respx.mock
async def test_status_code_found(settings):
    respx.get("https://t.example/alice").mock(
        return_value=httpx.Response(
            200,
            text='<html><head><meta property="og:title" content="Alice"></head></html>',
            headers={"content-type": "text/html"},
        )
    )
    source = DeclarativeSource(make_site())
    async with Fetcher(settings) as fetcher:
        result = await source.check(fetcher, "alice")
    assert result.status == "found"
    assert result.profile.display_name == "Alice"
    assert result.profile.url == "https://t.example/alice"


@respx.mock
async def test_status_code_missing(settings):
    respx.get("https://t.example/ghost").mock(return_value=httpx.Response(404))
    source = DeclarativeSource(make_site())
    async with Fetcher(settings) as fetcher:
        result = await source.check(fetcher, "ghost")
    assert result.status == "not_found"


@respx.mock
async def test_message_check(settings):
    site = make_site(error_type="message", error_msg=["No such user", "<title>404</title>"])
    respx.get("https://t.example/ghost").mock(
        return_value=httpx.Response(
            200, text="<title>404</title>", headers={"content-type": "text/html"}
        )
    )
    respx.get("https://t.example/alice").mock(
        return_value=httpx.Response(
            200, text="<title>Alice</title><h1>Alice</h1>", headers={"content-type": "text/html"}
        )
    )
    source = DeclarativeSource(site)
    async with Fetcher(settings) as fetcher:
        assert (await source.check(fetcher, "ghost")).status == "not_found"
        assert (await source.check(fetcher, "alice")).status == "found"


@respx.mock
async def test_response_url_check(settings):
    site = make_site(error_type="response_url", error_url="https://t.example/error")
    respx.get("https://t.example/alice").mock(
        return_value=httpx.Response(200, text="<title>alice profile</title>")
    )
    source = DeclarativeSource(site)
    async with Fetcher(settings) as fetcher:
        assert (await source.check(fetcher, "alice")).status == "found"


@respx.mock
async def test_regex_rejection_skips_network(settings):
    site = make_site(regex="^[a-z]{3}$")
    source = DeclarativeSource(site)
    async with Fetcher(settings) as fetcher:
        result = await source.check(fetcher, "alice")
    assert result.status == "not_found"
    assert "regex" in (result.detail or "")


@respx.mock
async def test_url_probe_is_used_for_request(settings):
    site = make_site(url_probe="https://t.example/api/{username}")
    respx.get("https://t.example/api/alice").mock(
        return_value=httpx.Response(200, text="<title>alice profile</title>")
    )
    source = DeclarativeSource(site)
    async with Fetcher(settings) as fetcher:
        result = await source.check(fetcher, "alice")
    assert result.status == "found"
    assert result.profile.url == "https://t.example/alice"


@respx.mock
async def test_challenge_and_generic_pages_are_not_profiles(settings):
    from larpharvester.http import BlockedError

    site = make_site(name="APClips", url="https://apclips.com/{username}")
    source = DeclarativeSource(site)
    for body in (
        "<title>Security Verification</title>",
        "<title>Client Challenge</title>",
    ):
        respx.get("https://apclips.com/simonw").mock(
            return_value=httpx.Response(200, text=body, headers={"content-type": "text/html"})
        )
        async with Fetcher(settings) as fetcher:
            with pytest.raises(BlockedError):
                await source.check(fetcher, "simonw")
    for body in (
        "<title>APClips.com</title>",
        "<title>APClips - Home</title>",
        "<html><body>no metadata</body></html>",
    ):
        respx.get("https://apclips.com/simonw").mock(
            return_value=httpx.Response(200, text=body, headers={"content-type": "text/html"})
        )
        async with Fetcher(settings) as fetcher:
            result = await source.check(fetcher, "simonw")
        assert result.status == "not_found", body

    respx.get("https://apclips.com/simonw").mock(
        return_value=httpx.Response(
            200, text="<title>SimonW on APClips</title>", headers={"content-type": "text/html"}
        )
    )
    async with Fetcher(settings) as fetcher:
        assert (await source.check(fetcher, "simonw")).status == "found"


def test_declarative_source_name_and_group():
    source = DeclarativeSource(make_site(name="About.me"))
    assert source.name == "web.about-me"
    assert source.group == "web"
    assert source.label == "About.me"
