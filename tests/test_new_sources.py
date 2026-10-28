from __future__ import annotations

import httpx
import pytest
import respx

from coldtrail.config import Settings
from coldtrail.http import Fetcher
from coldtrail.sources import SOURCES


@pytest.fixture
def settings(tmp_path):
    return Settings(db_path=tmp_path / "t.db", requests_per_second=0, jitter=0)


@respx.mock
async def test_steam(settings):
    respx.get("https://steamcommunity.com/id/alice").mock(
        return_value=httpx.Response(
            200,
            text="""<profile><steamID64>123</steamID64><steamID>Alice</steamID>
            <avatarFull>https://x/a.jpg</avatarFull><summary>hi</summary>
            <timecreated>1600000000</timecreated><realname>Alice A</realname>
            <location>Lisbon</location><privacyState>public</privacyState></profile>""",
            headers={"content-type": "text/xml"},
        )
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["steam"].check(fetcher, "alice")
    assert result.status == "found"
    assert result.profile.display_name == "Alice"
    assert result.profile.extra["steamid64"] == "123"
    assert result.profile.extra["realname"] == "Alice A"


@respx.mock
async def test_steam_missing(settings):
    respx.get("https://steamcommunity.com/id/ghost").mock(
        return_value=httpx.Response(200, text="<profile><error>no such user</error></profile>")
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["steam"].check(fetcher, "ghost")
    assert result.status == "not_found"


@respx.mock
async def test_chesscom(settings):
    respx.get("https://api.chess.com/pub/player/alice").mock(
        return_value=httpx.Response(
            200,
            json={
                "username": "Alice",
                "name": "Alice A",
                "avatar": "https://x/a.png",
                "location": "Lisbon",
                "joined": 1600000000,
                "followers": 3,
                "url": "https://www.chess.com/member/alice",
            },
        )
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["chesscom"].check(fetcher, "alice")
    assert result.status == "found"
    assert result.profile.followers == 3


@respx.mock
async def test_lichess(settings):
    respx.get("https://lichess.org/api/user/alice").mock(
        return_value=httpx.Response(
            200,
            json={
                "username": "Alice",
                "url": "https://lichess.org/@/Alice",
                "createdAt": 1600000000000,
                "profile": {"realName": "Alice A", "bio": "hi", "location": "Lisbon"},
            },
        )
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["lichess"].check(fetcher, "alice")
    assert result.status == "found"
    assert result.profile.display_name == "Alice A"


@respx.mock
async def test_roblox(settings):
    respx.post("https://users.roblox.com/v1/usernames/users").mock(
        return_value=httpx.Response(200, json={"data": [{"id": 42, "name": "Alice"}]})
    )
    respx.get("https://users.roblox.com/v1/users/42").mock(
        return_value=httpx.Response(
            200,
            json={
                "name": "Alice",
                "displayName": "Alice A",
                "description": "hi",
                "created": "2020-01-01T00:00:00Z",
            },
        )
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["roblox"].check(fetcher, "alice")
    assert result.status == "found"
    assert result.profile.extra["id"] == 42


@respx.mock
async def test_duolingo(settings):
    respx.get("https://www.duolingo.com/2017-06-30/users").mock(
        return_value=httpx.Response(
            200,
            json={
                "users": [
                    {
                        "id": 1,
                        "username": "alice",
                        "name": "Alice",
                        "bio": "hi",
                        "picture": "https://x/a.png",
                        "creationDate": 1600000000,
                    }
                ]
            },
        )
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["duolingo"].check(fetcher, "alice")
    assert result.status == "found"
    assert result.profile.username == "alice"


@respx.mock
async def test_telegram(settings):
    respx.get("https://t.me/alice").mock(
        return_value=httpx.Response(
            200,
            text="""<html><div class="tgme_page_title">Alice</div>
            <div class="tgme_page_extra">1 234 subscribers</div>
            <div class="tgme_page_description">hi</div></html>""",
            headers={"content-type": "text/html"},
        )
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["telegram"].check(fetcher, "alice")
    assert result.status == "found"
    assert result.profile.display_name == "Alice"
    assert result.profile.extra["extra"] == "1 234 subscribers"


@respx.mock
async def test_youtube(settings):
    respx.get("https://www.youtube.com/oembed").mock(
        return_value=httpx.Response(
            200,
            json={
                "author_name": "Alice",
                "author_url": "https://www.youtube.com/@alice",
                "title": "Alice channel",
                "thumbnail_url": "https://x/a.jpg",
            },
        )
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["youtube"].check(fetcher, "@alice")
    assert result.status == "found"
    assert result.profile.url == "https://www.youtube.com/@alice"


@respx.mock
async def test_stackoverflow(settings):
    respx.get("https://api.stackexchange.com/2.3/users").mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [
                    {
                        "user_id": 1,
                        "display_name": "Alice",
                        "link": "https://stackoverflow.com/users/1/alice",
                        "reputation": 100,
                        "profile_image": "https://x/a.png",
                    }
                ]
            },
        )
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["stackoverflow"].check(fetcher, "alice")
    assert result.status == "found"
    assert result.profile.extra["reputation"] == 100


@respx.mock
async def test_codeberg(settings):
    respx.get("https://codeberg.org/api/v1/users/alice").mock(
        return_value=httpx.Response(
            200,
            json={
                "login": "alice",
                "full_name": "Alice A",
                "description": "hi",
                "html_url": "https://codeberg.org/alice",
                "created": "2020-01-01T00:00:00Z",
                "followers_count": 4,
            },
        )
    )
    respx.get("https://codeberg.org/api/v1/users/alice/keys").mock(
        return_value=httpx.Response(200, json=[])
    )
    respx.get("https://codeberg.org/api/v1/users/alice/gpg_keys").mock(
        return_value=httpx.Response(200, json=[])
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["codeberg"].check(fetcher, "alice")
    assert result.status == "found"
    assert result.profile.followers == 4


@respx.mock
async def test_huggingface(settings):
    respx.get("https://huggingface.co/api/users/alice/overview").mock(
        return_value=httpx.Response(
            200,
            json={
                "user": "alice",
                "fullname": "Alice A",
                "numModels": 2,
                "numFollowers": 7,
            },
        )
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["huggingface"].check(fetcher, "alice")
    assert result.status == "found"
    assert result.profile.extra["models"] == 2


@respx.mock
async def test_pgp(settings):
    respx.get("https://keyserver.ubuntu.com/pks/lookup").mock(
        return_value=httpx.Response(
            200,
            text="info:1:1\npub:ABCD:1:2048:1600000000::\n"
            "uid:Alice%20%3Calice%40example.com%3E:1600000000::\n",
            headers={"content-type": "text/plain"},
        )
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["pgp"].check(fetcher, "alice@example.com")
    assert result.status == "found"
    assert result.profile.display_name == "Alice <alice@example.com>"


@respx.mock
async def test_github_commits(settings):
    respx.get("https://api.github.com/search/commits").mock(
        return_value=httpx.Response(
            200,
            json={
                "total_count": 12,
                "items": [
                    {
                        "html_url": "https://github.com/a/b/commit/1",
                        "author": {"login": "alice"},
                        "repository": {"full_name": "a/b"},
                    }
                ],
            },
        )
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["github-commits"].check(fetcher, "alice@example.com")
    assert result.status == "found"
    assert result.profile.username == "alice"
    assert result.profile.extra["commits"] == 12


@respx.mock
async def test_hibp(settings):
    settings.hibp_api_key = "k"
    respx.get("https://haveibeenpwned.com/api/v3/breachedaccount/alice@example.com").mock(
        return_value=httpx.Response(
            200,
            json=[{"Name": "Adobe", "Title": "Adobe", "BreachDate": "2013-10-04", "PwnCount": 1}],
        )
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["hibp"].check(fetcher, "alice@example.com")
    assert result.status == "found"
    assert result.profile.extra["count"] == 1


async def test_hibp_without_key(settings):
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["hibp"].check(fetcher, "alice@example.com")
    assert result.status == "blocked"
    assert "HIBP_API_KEY" in (result.detail or "")


@respx.mock
async def test_emailrep(settings):
    settings.emailrep_api_key = "k"
    respx.get("https://emailrep.io/alice@example.com").mock(
        return_value=httpx.Response(
            200,
            json={
                "email": "alice@example.com",
                "reputation": "high",
                "suspicious": False,
                "details": {"profiles": ["https://github.com/alice"]},
            },
        )
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["emailrep"].check(fetcher, "alice@example.com")
    assert result.status == "found"
    assert result.profile.extra["accounts"][0]["url"] == "https://github.com/alice"
