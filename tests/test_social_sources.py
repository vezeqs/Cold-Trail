"""Native social/media sources added in 0.7.0 (no network: respx)."""

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


def _html(title: str, description: str = "bio", image: str = "https://x/a.jpg") -> str:
    return (
        "<!doctype html><html><head>"
        f'<meta property="og:title" content="{title}">'
        f'<meta property="og:description" content="{description}">'
        f'<meta property="og:image" content="{image}">'
        "</head><body></body></html>"
    )


@respx.mock
async def test_threads_found(settings):
    respx.get("https://www.threads.net/@alice").mock(
        return_value=httpx.Response(
            200,
            text=_html("Alice (@alice) on Threads"),
            headers={"content-type": "text/html"},
        )
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["threads"].check(fetcher, "alice")
    assert result.status == "found"
    assert result.profile.display_name == "Alice"
    assert result.profile.bio == "bio"


@respx.mock
async def test_threads_missing(settings):
    respx.get("https://www.threads.net/@ghost").mock(return_value=httpx.Response(404))
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["threads"].check(fetcher, "ghost")
    assert result.status == "not_found"


@respx.mock
async def test_threads_login_wall_is_blocked(settings):
    respx.get("https://www.threads.net/@alice").mock(
        return_value=httpx.Response(
            200,
            text="<html><body>Log in to Threads to see this profile.</body></html>",
            headers={"content-type": "text/html"},
        )
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["threads"].check(fetcher, "alice")
    assert result.status == "blocked"


@respx.mock
async def test_pinterest_found(settings):
    respx.get("https://www.pinterest.com/alice/").mock(
        return_value=httpx.Response(
            200,
            text=_html("Alice (alice) - Profile | Pinterest"),
            headers={"content-type": "text/html"},
        )
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["pinterest"].check(fetcher, "alice")
    assert result.status == "found"
    assert result.profile.display_name == "Alice"


@respx.mock
async def test_tumblr_found(settings):
    respx.get("https://alice.tumblr.com/").mock(
        return_value=httpx.Response(
            200,
            text=_html("Alice — Tumblr"),
            headers={"content-type": "text/html"},
        )
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["tumblr"].check(fetcher, "Alice")
    assert result.status == "found"
    assert result.profile.username == "alice"


async def test_tumblr_rejects_invalid_blog_name(settings):
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["tumblr"].check(fetcher, "not a blog")
    assert result.status == "not_found"


@respx.mock
async def test_vk_found_and_missing(settings):
    respx.get("https://vk.com/alice").mock(
        return_value=httpx.Response(
            200, text=_html("Alice | VK"), headers={"content-type": "text/html"}
        )
    )
    respx.get("https://vk.com/ghost").mock(
        return_value=httpx.Response(
            200, text=_html("User not found"), headers={"content-type": "text/html"}
        )
    )
    async with Fetcher(settings) as fetcher:
        found = await SOURCES["vk"].check(fetcher, "alice")
        missing = await SOURCES["vk"].check(fetcher, "ghost")
    assert found.status == "found"
    assert found.profile.display_name == "Alice"
    assert missing.status == "not_found"


@respx.mock
async def test_snapchat_found(settings):
    respx.get("https://www.snapchat.com/add/alice").mock(
        return_value=httpx.Response(
            200,
            text=_html("Alice | Snapchat"),
            headers={"content-type": "text/html"},
        )
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["snapchat"].check(fetcher, "alice")
    assert result.status == "found"
    assert result.profile.display_name == "Alice"


@respx.mock
async def test_instagram_found(settings):
    respx.get("https://www.instagram.com/alice/").mock(
        return_value=httpx.Response(
            200,
            text=_html("Alice (@alice) • Instagram photos and videos"),
            headers={"content-type": "text/html"},
        )
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["instagram"].check(fetcher, "alice")
    assert result.status == "found"
    assert result.profile.display_name == "Alice"


@respx.mock
async def test_instagram_login_wall_is_blocked(settings):
    respx.get("https://www.instagram.com/alice/").mock(
        return_value=httpx.Response(
            200,
            text="<html><body>Login • Instagram</body></html>",
            headers={"content-type": "text/html"},
        )
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["instagram"].check(fetcher, "alice")
    assert result.status == "blocked"


async def test_x_requires_token(settings):
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["x"].check(fetcher, "alice")
    assert result.status == "blocked"
    assert "X_BEARER_TOKEN" in result.detail


@respx.mock
async def test_x_found_with_token(settings):
    settings.x_bearer_token = "token"
    respx.get(
        "https://api.x.com/2/users/by/username/alice",
        params={
            "user.fields": (
                "created_at,description,location,profile_image_url,public_metrics,url,verified"
            )
        },
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "id": "42",
                    "username": "alice",
                    "name": "Alice",
                    "description": "bio alice@example.com",
                    "location": "Lisbon",
                    "url": "https://alice.example",
                    "profile_image_url": "https://x/a.jpg",
                    "verified": True,
                    "public_metrics": {"followers_count": 10},
                }
            },
        )
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["x"].check(fetcher, "alice")
    assert result.status == "found"
    assert result.profile.followers == 10
    assert result.profile.extra["verified"] is True


async def test_hunter_requires_key(settings):
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["hunter"].check(fetcher, "alice@example.com")
    assert result.status == "blocked"
    assert "HUNTER_API_KEY" in result.detail


@respx.mock
async def test_hunter_verifies_email(settings):
    settings.hunter_api_key = "key"
    respx.get(
        "https://api.hunter.io/v2/email-verifier",
        params={"email": "alice@example.com", "api_key": "key"},
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "status": "valid",
                    "result": "deliverable",
                    "score": 95,
                    "disposable": False,
                    "webmail": False,
                    "accept_all": False,
                    "mx_records": True,
                    "smtp_check": True,
                    "sources": [{"domain": "example.com", "uri": "https://example.com"}],
                }
            },
        )
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["hunter"].check(fetcher, "alice@example.com")
    assert result.status == "found"
    assert result.profile.extra["score"] == 95
