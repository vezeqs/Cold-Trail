"""Search-provider tests (no network)."""

from __future__ import annotations

import httpx
import pytest
import respx

from coldtrail.config import Settings
from coldtrail.http import Fetcher
from coldtrail.websearch import search


@pytest.fixture
def settings(tmp_path):
    return Settings(db_path=tmp_path / "t.db", requests_per_second=0, jitter=0)


@respx.mock
async def test_serper_results(settings):
    settings.serper_api_key = "key"
    respx.post("https://google.serper.dev/search").mock(
        return_value=httpx.Response(
            200,
            json={
                "organic": [{"title": "Example", "link": "https://example.com", "snippet": "hi"}]
            },
        )
    )
    async with Fetcher(settings) as fetcher:
        provider, results = await search(fetcher, "example", settings)
    assert provider == "serper"
    assert results == [{"title": "Example", "url": "https://example.com", "snippet": "hi"}]


@respx.mock
async def test_brave_results(settings):
    settings.brave_api_key = "key"
    respx.get("https://api.search.brave.com/res/v1/web/search").mock(
        return_value=httpx.Response(
            200,
            json={
                "web": {
                    "results": [{"title": "Brave", "url": "https://b.example", "description": "d"}]
                }
            },
        )
    )
    async with Fetcher(settings) as fetcher:
        provider, results = await search(fetcher, "q", settings, provider="brave")
    assert provider == "brave"
    assert results[0]["url"] == "https://b.example"


@respx.mock
async def test_searxng_results(settings):
    settings.searxng_url = "https://searx.example"
    respx.get("https://searx.example/search").mock(
        return_value=httpx.Response(
            200,
            json={"results": [{"title": "S", "url": "https://s.example", "content": "c"}]},
        )
    )
    async with Fetcher(settings) as fetcher:
        provider, results = await search(fetcher, "q", settings, provider="searxng")
    assert provider == "searxng"
    assert results[0]["title"] == "S"


@respx.mock
async def test_duckduckgo_html(settings):
    respx.get("https://html.duckduckgo.com/html/").mock(
        return_value=httpx.Response(
            200,
            text='<div class="result"><a class="result__a" href="https://duckduckgo.com/l/?uddg=https%3A%2F%2Ftarget.example%2Fx">DDG</a>'
            '<a class="result__snippet">snip</a></div>',
            headers={"content-type": "text/html"},
        )
    )
    async with Fetcher(settings) as fetcher:
        provider, results = await search(fetcher, "q", settings)
    assert provider == "duckduckgo"
    assert results == [{"title": "DDG", "url": "https://target.example/x", "snippet": "snip"}]
