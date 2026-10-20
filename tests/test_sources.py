from __future__ import annotations

import hashlib

import httpx
import pytest
import respx

from larpharvester.config import Settings
from larpharvester.http import Fetcher
from larpharvester.sources import SOURCES


@pytest.fixture
def settings(tmp_path):
    return Settings(db_path=tmp_path / "test.db")


@respx.mock
async def test_github_found(settings):
    respx.get("https://api.github.com/users/octocat").mock(
        return_value=httpx.Response(
            200,
            json={
                "login": "octocat",
                "html_url": "https://github.com/octocat",
                "name": "The Octocat",
                "bio": "Mascot",
                "avatar_url": "https://avatars.example/u/1",
                "blog": "https://github.blog",
                "created_at": "2011-01-25T18:44:36Z",
                "followers": 9000,
                "public_repos": 8,
            },
        )
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["github"].check(fetcher, "octocat")
    assert result.status == "found"
    assert result.profile.username == "octocat"
    assert result.profile.followers == 9000
    assert result.profile.extra["public_repos"] == 8


@respx.mock
async def test_github_missing(settings):
    respx.get("https://api.github.com/users/ghost").mock(return_value=httpx.Response(404))
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["github"].check(fetcher, "ghost")
    assert result.status == "not_found"


@respx.mock
async def test_github_rate_limited(settings):
    respx.get("https://api.github.com/users/octocat").mock(
        return_value=httpx.Response(403, json={"message": "API rate limit exceeded"})
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["github"].check(fetcher, "octocat")
    assert result.status == "blocked"
    assert "GITHUB_TOKEN" in (result.detail or "")


@respx.mock
async def test_github_posts(settings):
    respx.get("https://api.github.com/users/octocat/events/public").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "id": "1",
                    "type": "PushEvent",
                    "repo": {"name": "octocat/hello-world"},
                    "created_at": "2024-01-01T00:00:00Z",
                    "payload": {"commits": [{}, {}]},
                }
            ],
        )
    )
    async with Fetcher(settings) as fetcher:
        posts = await SOURCES["github"].posts(fetcher, "octocat", 10)
    assert len(posts) == 1
    assert posts[0].url == "https://github.com/octocat/hello-world"
    assert posts[0].metrics["commits"] == 2


@respx.mock
async def test_reddit_found(settings):
    respx.get("https://www.reddit.com/user/spez/about.json").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "name": "spez",
                    "icon_img": "https://styles.example/snoo.png",
                    "created_utc": 1118030400,
                    "total_karma": 100,
                    "subreddit": {"public_description": "<p>Reddit CEO</p>"},
                }
            },
        )
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["reddit"].check(fetcher, "spez")
    assert result.status == "found"
    assert result.profile.bio == "Reddit CEO"
    assert result.profile.created_at.startswith("2005-06-06")


@respx.mock
async def test_reddit_blocked(settings):
    respx.get("https://www.reddit.com/user/spez/about.json").mock(return_value=httpx.Response(403))
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["reddit"].check(fetcher, "spez")
    assert result.status == "blocked"


@respx.mock
async def test_hackernews_found(settings):
    respx.get("https://hacker-news.firebaseio.com/v0/user/pg.json").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "pg",
                "karma": 100,
                "created": 1160418111,
                "about": "<p>Founder</p>",
                "submitted": [1, 2, 3],
            },
        )
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["hackernews"].check(fetcher, "pg")
    assert result.status == "found"
    assert result.profile.bio == "Founder"
    assert result.profile.extra == {"karma": 100, "submitted": 3}


@respx.mock
async def test_hackernews_missing_returns_null(settings):
    respx.get("https://hacker-news.firebaseio.com/v0/user/ghost.json").mock(
        return_value=httpx.Response(200, text="null")
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["hackernews"].check(fetcher, "ghost")
    assert result.status == "not_found"


@respx.mock
async def test_devto_missing(settings):
    respx.get("https://dev.to/api/users/by_username").mock(return_value=httpx.Response(404))
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["devto"].check(fetcher, "nobody")
    assert result.status == "not_found"


@respx.mock
async def test_mastodon_found(settings):
    settings.mastodon_instances = ("mastodon.social",)
    respx.get("https://mastodon.social/api/v1/accounts/lookup").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "42",
                "username": "alice",
                "acct": "alice",
                "display_name": "Alice",
                "note": "<p>Hello <a href='#'>world</a></p>",
                "avatar": "https://files.example/a.png",
                "url": "https://mastodon.social/@alice",
                "created_at": "2020-01-01T00:00:00Z",
                "followers_count": 12,
                "fields": [{"name": "Site", "value": "<a href='https://alice.dev'>alice.dev</a>"}],
            },
        )
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["mastodon"].check(fetcher, "alice")
    assert result.status == "found"
    assert result.profile.bio == "Hello world"
    assert result.profile.extra["instance"] == "mastodon.social"


@respx.mock
async def test_bluesky_found(settings):
    respx.get("https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile").mock(
        return_value=httpx.Response(
            200,
            json={
                "did": "did:plc:abc",
                "handle": "alice.bsky.social",
                "displayName": "Alice",
                "description": "hi",
                "avatar": "https://cdn.example/a.jpg",
                "createdAt": "2023-04-01T00:00:00Z",
                "followersCount": 5,
            },
        )
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["bluesky"].check(fetcher, "alice.bsky.social")
    assert result.status == "found"
    assert result.profile.extra["did"] == "did:plc:abc"


@respx.mock
async def test_bluesky_posts(settings):
    respx.get("https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile").mock(
        return_value=httpx.Response(200, json={"did": "did:plc:abc", "handle": "alice.bsky.social"})
    )
    respx.get("https://public.api.bsky.app/xrpc/com.atproto.repo.listRecords").mock(
        return_value=httpx.Response(
            200,
            json={
                "records": [
                    {
                        "uri": "at://did:plc:abc/app.bsky.feed.post/3kabc",
                        "value": {"text": "hello", "createdAt": "2024-01-01T00:00:00Z"},
                    }
                ]
            },
        )
    )
    async with Fetcher(settings) as fetcher:
        posts = await SOURCES["bluesky"].posts(fetcher, "alice.bsky.social", 5)
    assert len(posts) == 1
    assert posts[0].url == "https://bsky.app/profile/alice.bsky.social/post/3kabc"


@respx.mock
async def test_gravatar_found(settings):
    email = "Alice@Example.com"
    digest = hashlib.md5(email.strip().casefold().encode()).hexdigest()
    respx.get(f"https://gravatar.com/{digest}.json").mock(
        return_value=httpx.Response(
            200,
            json={
                "entry": [
                    {
                        "preferredUsername": "alice",
                        "displayName": "Alice",
                        "aboutMe": "hi",
                        "profileUrl": "https://gravatar.com/alice",
                        "thumbnailUrl": "https://gravatar.com/avatar/x",
                        "accounts": [
                            {
                                "shortname": "github",
                                "username": "alice",
                                "url": "https://github.com/alice",
                            }
                        ],
                    }
                ]
            },
        )
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["gravatar"].check(fetcher, email)
    assert result.status == "found"
    assert result.profile.username == "alice"
    assert result.profile.extra["accounts"][0]["username"] == "alice"


@respx.mock
async def test_gravatar_missing(settings):
    email = "nobody@example.com"
    digest = hashlib.md5(email.encode()).hexdigest()
    respx.get(f"https://gravatar.com/{digest}.json").mock(return_value=httpx.Response(404))
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["gravatar"].check(fetcher, email)
    assert result.status == "not_found"


@respx.mock
async def test_keybase_found(settings):
    respx.get("https://keybase.io/_/api/1.0/user/lookup.json").mock(
        return_value=httpx.Response(
            200,
            json={
                "status": {"code": 0, "name": "OK"},
                "them": [
                    {
                        "basics": {"username": "alice", "uid": "u1"},
                        "profile": {"full_name": "Alice", "bio": "hi", "location": "Lisbon"},
                        "pictures": {"primary": {"url": "https://keybase.io/a.png"}},
                        "proofs_summary": {
                            "all": [
                                {
                                    "proof_type": "github",
                                    "nametag": "alicegh",
                                    "proof_url": "https://gist.github.com/x",
                                }
                            ]
                        },
                    }
                ],
            },
        )
    )
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["keybase"].check(fetcher, "alice@example.com")
    assert result.status == "found"
    assert result.profile.username == "alice"
    assert result.profile.extra["proofs"][0]["username"] == "alicegh"


@respx.mock
async def test_retries_on_429_then_succeeds(settings, monkeypatch):
    monkeypatch.setattr("larpharvester.http.BACKOFF", 0)
    route = respx.get("https://api.github.com/users/octocat")
    route.side_effect = [
        httpx.Response(429, headers={"Retry-After": "0"}),
        httpx.Response(200, json={"login": "octocat"}),
    ]
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["github"].check(fetcher, "octocat")
    assert result.status == "found"
    assert route.call_count == 2
