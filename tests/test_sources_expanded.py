"""Tests for the expanded source corpus: social/creator, dev registries, and
email/breach sources added in 0.4.0."""

from __future__ import annotations

import httpx
import pytest
import respx

from larpharvester.config import Settings
from larpharvester.http import Fetcher
from larpharvester.sources import SOURCES


@pytest.fixture
def settings(tmp_path):
    return Settings(db_path=tmp_path / "t.db", requests_per_second=0, jitter=0)


async def _check(settings, name: str, target: str):
    async with Fetcher(settings) as fetcher:
        return await SOURCES[name].check(fetcher, target)


# -- dev registries ---------------------------------------------------------


@respx.mock
async def test_crates_found(settings):
    respx.get("https://crates.io/api/v1/users/alice").mock(
        return_value=httpx.Response(
            200,
            json={
                "user": {
                    "id": 7,
                    "login": "alice",
                    "name": "Alice",
                    "avatar": "https://x/a.png",
                    "url": "https://crates.io/users/alice",
                }
            },
        )
    )
    result = await _check(settings, "crates", "alice")
    assert result.status == "found"
    assert result.profile.username == "alice"
    assert result.profile.display_name == "Alice"


@respx.mock
async def test_crates_missing(settings):
    respx.get("https://crates.io/api/v1/users/ghost").mock(return_value=httpx.Response(404))
    result = await _check(settings, "crates", "ghost")
    assert result.status == "not_found"


@respx.mock
async def test_dockerhub_found(settings):
    respx.get("https://hub.docker.com/v2/users/alice/").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "1",
                "username": "alice",
                "full_name": "Alice A",
                "company": "ACME",
                "location": "Lisbon",
                "gravatar_url": "https://x/a.png",
                "profile_url": "https://alice.dev",
                "date_joined": "2020-01-01T00:00:00Z",
                "type": "User",
            },
        )
    )
    result = await _check(settings, "dockerhub", "alice")
    assert result.status == "found"
    assert result.profile.website == "https://alice.dev"
    assert result.profile.extra["company"] == "ACME"


@respx.mock
async def test_dockerhub_org_uses_orgname(settings):
    respx.get("https://hub.docker.com/v2/users/docker/").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "57b4",
                "orgname": "docker",
                "full_name": "Docker, Inc.",
                "profile_url": "https://www.docker.com",
            },
        )
    )
    result = await _check(settings, "dockerhub", "docker")
    assert result.status == "found"
    assert result.profile.username == "docker"
    assert result.profile.extra["type"] == "org"


@respx.mock
async def test_rubygems_found_with_twitter(settings):
    respx.get("https://rubygems.org/api/v1/profiles/alice.json").mock(
        return_value=httpx.Response(
            200,
            json={"id": 5, "handle": "alice", "avatar": None, "twitter": "@alice_tw"},
        )
    )
    result = await _check(settings, "rubygems", "alice")
    assert result.status == "found"
    assert result.profile.extra["accounts"][0]["username"] == "alice_tw"


@respx.mock
async def test_packagist_found(settings):
    respx.get("https://packagist.org/packages/list.json", params={"vendor": "alice"}).mock(
        return_value=httpx.Response(200, json={"packageNames": ["alice/foo", "alice/bar"]})
    )
    result = await _check(settings, "packagist", "alice")
    assert result.status == "found"
    assert result.profile.extra["package_count"] == 2


@respx.mock
async def test_packagist_missing(settings):
    respx.get("https://packagist.org/packages/list.json", params={"vendor": "ghost"}).mock(
        return_value=httpx.Response(200, json={"packageNames": []})
    )
    result = await _check(settings, "packagist", "ghost")
    assert result.status == "not_found"


# -- social / creator platforms --------------------------------------------


@respx.mock
async def test_tiktok_sigi_found(settings):
    payload = {
        "__DEFAULT_SCOPE__": {
            "webapp.user-detail": {
                "userInfo": {
                    "user": {
                        "id": "99",
                        "uniqueId": "alice",
                        "nickname": "Alice",
                        "signature": "hello",
                        "avatarLarger": "https://x/a.jpg",
                        "verified": True,
                        "bioLink": {"link": "https://alice.dev"},
                    },
                    "stats": {
                        "followerCount": 1200,
                        "followingCount": 10,
                        "heartCount": 5000,
                        "videoCount": 22,
                    },
                }
            }
        }
    }
    html = (
        '<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__" type="application/json">'
        + __import__("json").dumps(payload)
        + "</script>"
    )
    respx.get("https://www.tiktok.com/@alice").mock(
        return_value=httpx.Response(200, text=html, headers={"content-type": "text/html"})
    )
    result = await _check(settings, "tiktok", "alice")
    assert result.status == "found"
    assert result.profile.followers == 1200
    assert result.profile.website == "https://alice.dev"


@respx.mock
async def test_tiktok_missing(settings):
    respx.get("https://www.tiktok.com/@ghost").mock(
        return_value=httpx.Response(404, text="not found")
    )
    result = await _check(settings, "tiktok", "ghost")
    assert result.status == "not_found"


@respx.mock
async def test_tiktok_sigi_status_means_missing(settings):
    payload = {"__DEFAULT_SCOPE__": {"webapp.user-detail": {"statusCode": 10221}}}
    html = (
        '<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__" type="application/json">'
        + __import__("json").dumps(payload)
        + "</script>"
    )
    respx.get("https://www.tiktok.com/@ghost").mock(
        return_value=httpx.Response(200, text=html, headers={"content-type": "text/html"})
    )
    result = await _check(settings, "tiktok", "ghost")
    assert result.status == "not_found"


@respx.mock
async def test_medium_found_and_posts(settings):
    respx.get("https://medium.com/@alice").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Stories by Alice – Medium</title>"
            '<meta name="description" content="writer"></head></html>',
            headers={"content-type": "text/html"},
        )
    )
    rss = """<?xml version="1.0"?><rss><channel>
      <item><title>First post</title><link>https://medium.com/p/1</link>
        <guid>1</guid><pubDate>Mon, 01 Jan 2024 10:00:00 GMT</pubDate>
        <description>&lt;p&gt;hello world&lt;/p&gt;</description></item>
      <item><title>Second post</title><link>https://medium.com/p/2</link>
        <guid>2</guid><pubDate>Tue, 02 Jan 2024 10:00:00 GMT</pubDate>
        <description>second</description></item>
    </channel></rss>"""
    respx.get("https://medium.com/feed/@alice").mock(
        return_value=httpx.Response(200, text=rss, headers={"content-type": "application/rss+xml"})
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["medium"].check(fetcher, "alice")
        posts = await SOURCES["medium"].posts(fetcher, "alice", 10)
    assert result.status == "found"
    assert result.profile.display_name == "Alice"
    assert len(posts) == 2
    assert posts[0].post_id == "1"
    assert "hello world" in posts[0].text
    assert posts[0].created_at.startswith("2024-01-01")


@respx.mock
async def test_medium_posts_respect_limit(settings):
    rss = """<?xml version="1.0"?><rss><channel>
      <item><title>a</title><guid>1</guid><pubDate>Mon, 01 Jan 2024 10:00:00 GMT</pubDate></item>
      <item><title>b</title><guid>2</guid><pubDate>Tue, 02 Jan 2024 10:00:00 GMT</pubDate></item>
    </channel></rss>"""
    respx.get("https://medium.com/feed/@alice").mock(return_value=httpx.Response(200, text=rss))
    async with Fetcher(settings) as fetcher:
        posts = await SOURCES["medium"].posts(fetcher, "alice", 1)
    assert len(posts) == 1


@respx.mock
async def test_linktree_found(settings):
    payload = {
        "props": {
            "pageProps": {
                "account": {
                    "username": "alice",
                    "pageTitle": "Alice",
                    "description": "links",
                    "profilePictureUrl": "https://x/a.png",
                    "links": [{"title": "Site", "url": "https://alice.dev"}],
                    "socialLinks": [{"type": "github", "url": "https://github.com/alice"}],
                }
            }
        }
    }
    html = (
        '<script id="__NEXT_DATA__" type="application/json">'
        + __import__("json").dumps(payload)
        + "</script>"
    )
    respx.get("https://linktr.ee/alice").mock(
        return_value=httpx.Response(200, text=html, headers={"content-type": "text/html"})
    )
    result = await _check(settings, "linktree", "alice")
    assert result.status == "found"
    assert result.profile.website == "https://alice.dev"
    assert len(result.profile.extra["accounts"]) == 2


@respx.mock
async def test_substack_found(settings):
    respx.get("https://substack.com/@alice").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Alice's Newsletter | Substack</title></head></html>",
            headers={"content-type": "text/html"},
        )
    )
    result = await _check(settings, "substack", "alice")
    assert result.status == "found"
    assert result.profile.display_name == "Alice's Newsletter"


@respx.mock
async def test_substack_search_page_is_not_a_profile(settings):
    respx.get("https://substack.com/@ghost").mock(
        return_value=httpx.Response(
            200,
            text='<html><head><title>Search "ghost" on Substack</title></head></html>',
            headers={"content-type": "text/html"},
        )
    )
    result = await _check(settings, "substack", "ghost")
    assert result.status == "not_found"


@respx.mock
async def test_matrix_found(settings):
    url = "https://matrix-client.matrix.org/_matrix/client/v3/profile/%40alice%3Amatrix.org"
    respx.get(url).mock(
        return_value=httpx.Response(
            200, json={"displayname": "Alice", "avatar_url": "mxc://matrix.org/abc"}
        )
    )
    result = await _check(settings, "matrix", "alice")
    assert result.status == "found"
    assert result.profile.extra["mxid"] == "@alice:matrix.org"
    assert result.profile.avatar.endswith("/abc")


@respx.mock
async def test_matrix_explicit_server(settings):
    url = "https://matrix-client.matrix.org/_matrix/client/v3/profile/%40bob%3Aexample.org"
    respx.get(url).mock(return_value=httpx.Response(200, json={"displayname": "Bob"}))
    result = await _check(settings, "matrix", "@bob:example.org")
    assert result.status == "found"
    assert result.profile.extra["homeserver"] == "example.org"


# -- email / breach ---------------------------------------------------------


@respx.mock
async def test_hudsonrock_found(settings):
    respx.get(
        "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email",
        params={"email": "alice@example.com"},
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "message": "ok",
                "stealers": [
                    {
                        "computer_name": "DESKTOP-1",
                        "operating_system": "Windows 10",
                        "date_compromised": "2024-01-01T00:00:00Z",
                    }
                ],
            },
        )
    )
    result = await _check(settings, "hudsonrock", "alice@example.com")
    assert result.status == "found"
    assert result.profile.extra["stealer_count"] == 1


@respx.mock
async def test_hudsonrock_clean(settings):
    respx.get(
        "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email",
        params={"email": "clean@example.com"},
    ).mock(return_value=httpx.Response(200, json={"stealers": []}))
    result = await _check(settings, "hudsonrock", "clean@example.com")
    assert result.status == "not_found"


@respx.mock
async def test_leakcheck_found(settings):
    respx.get("https://leakcheck.io/api/public", params={"check": "alice@example.com"}).mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "found": 3,
                "fields": ["email", "password"],
                "sources": [{"name": "Collection1"}, {"name": "LinkedIn"}],
            },
        )
    )
    result = await _check(settings, "leakcheck", "alice@example.com")
    assert result.status == "found"
    assert result.profile.extra["found"] == 3


@respx.mock
async def test_leakcheck_clean(settings):
    respx.get("https://leakcheck.io/api/public", params={"check": "clean@example.com"}).mock(
        return_value=httpx.Response(200, json={"success": True, "found": 0})
    )
    result = await _check(settings, "leakcheck", "clean@example.com")
    assert result.status == "not_found"


@respx.mock
async def test_libravatar_found(settings):
    import hashlib

    digest = hashlib.sha256(b"alice@example.com").hexdigest()
    url = f"https://seccdn.libravatar.org/avatar/{digest}?d=404&s=200"
    respx.get(url).mock(
        return_value=httpx.Response(200, content=b"\x89PNG", headers={"content-type": "image/png"})
    )
    result = await _check(settings, "libravatar", "alice@example.com")
    assert result.status == "found"
    assert result.profile.extra["sha256"] == digest


@respx.mock
async def test_libravatar_missing(settings):
    import hashlib

    digest = hashlib.sha256(b"ghost@example.com").hexdigest()
    respx.get(f"https://seccdn.libravatar.org/avatar/{digest}?d=404&s=200").mock(
        return_value=httpx.Response(404)
    )
    result = await _check(settings, "libravatar", "ghost@example.com")
    assert result.status == "not_found"


# -- registry sanity --------------------------------------------------------


def test_all_new_sources_registered():
    expected = {
        "crates",
        "dockerhub",
        "rubygems",
        "packagist",
        "tiktok",
        "medium",
        "linktree",
        "substack",
        "matrix",
        "hudsonrock",
        "leakcheck",
        "libravatar",
    }
    assert expected <= set(SOURCES)


def test_new_source_groups_and_kinds():
    assert SOURCES["hudsonrock"].kind == "email"
    assert SOURCES["leakcheck"].kind == "email"
    assert SOURCES["libravatar"].kind == "email"
    assert SOURCES["tiktok"].kind == "username"
    assert SOURCES["medium"].supports_posts is True
    assert SOURCES["dockerhub"].group == "dev"
