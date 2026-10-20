from __future__ import annotations

import httpx
import pytest
import respx

from larpharvester.config import Settings
from larpharvester.http import BlockedError, BudgetExceeded, Fetcher, FetchError
from larpharvester.store import Store


@pytest.fixture
def settings(tmp_path):
    return Settings(db_path=tmp_path / "t.db", requests_per_second=0, jitter=0)


@respx.mock
async def test_cache_prevents_second_request(settings, tmp_path):
    route = respx.get("https://api.example/x").mock(return_value=httpx.Response(200, json={"a": 1}))
    with Store(settings.db_path) as store:
        async with Fetcher(settings, store=store) as fetcher:
            first = await fetcher.get_json("https://api.example/x")
            second = await fetcher.get_json("https://api.example/x")
    assert first == second == (200, {"a": 1})
    assert route.call_count == 1


@respx.mock
async def test_no_cache_forces_requests(settings, tmp_path):
    settings.cache_ttl = 0
    route = respx.get("https://api.example/x").mock(return_value=httpx.Response(200, json={"a": 1}))
    with Store(settings.db_path) as store:
        async with Fetcher(settings, store=store) as fetcher:
            await fetcher.get_json("https://api.example/x")
            await fetcher.get_json("https://api.example/x")
    assert route.call_count == 2


@respx.mock
async def test_budget_is_enforced(settings):
    settings.max_requests = 1
    respx.get("https://api.example/x").mock(return_value=httpx.Response(200, json={}))
    async with Fetcher(settings) as fetcher:
        await fetcher.get_json("https://api.example/x")
        with pytest.raises(BudgetExceeded):
            await fetcher.get_json("https://api.example/y")


@respx.mock
async def test_bot_wall_raises_blocked(settings):
    respx.get("https://api.example/x").mock(
        return_value=httpx.Response(
            200,
            text="<html><title>Just a moment...</title></html>",
            headers={"content-type": "text/html"},
        )
    )
    async with Fetcher(settings) as fetcher:
        with pytest.raises(BlockedError):
            await fetcher.get_json("https://api.example/x")


@respx.mock
async def test_html_instead_of_json_raises_blocked(settings):
    respx.get("https://api.example/x").mock(
        return_value=httpx.Response(
            200, text="<html>hi</html>", headers={"content-type": "text/html"}
        )
    )
    async with Fetcher(settings) as fetcher:
        with pytest.raises(BlockedError):
            await fetcher.get_json("https://api.example/x")


@respx.mock
async def test_404_is_returned_not_raised(settings):
    respx.get("https://api.example/x").mock(return_value=httpx.Response(404, json={"e": 1}))
    async with Fetcher(settings) as fetcher:
        assert await fetcher.get_json("https://api.example/x") == (404, {"e": 1})


async def test_replay_reads_raw(settings, tmp_path):
    with Store(settings.db_path) as store:
        store.raw_put("https://api.example/x", 200, b'{"a": 2}', None)
        settings.replay = True
        async with Fetcher(settings, store=store) as fetcher:
            assert await fetcher.get_json("https://api.example/x") == (200, {"a": 2})


async def test_replay_without_recording_raises(settings, tmp_path):
    with Store(settings.db_path) as store:
        settings.replay = True
        async with Fetcher(settings, store=store) as fetcher:
            with pytest.raises(FetchError):
                await fetcher.get_json("https://api.example/missing")


@respx.mock
async def test_etag_revalidation(settings, tmp_path):
    route = respx.get("https://api.example/x")
    route.side_effect = [
        httpx.Response(200, json={"a": 1}, headers={"etag": '"v1"'}),
        httpx.Response(304),
    ]
    with Store(settings.db_path) as store:
        async with Fetcher(settings, store=store) as fetcher:
            first = await fetcher.get_json("https://api.example/x")
            # expire the cache entry so the second call revalidates
            store.conn.execute("UPDATE http_cache SET fetched_at = '2000-01-01T00:00:00'")
            store.conn.commit()
            second = await fetcher.get_json("https://api.example/x")
    assert first == second == (200, {"a": 1})
    assert route.call_count == 2


@respx.mock
async def test_retries_on_500(settings):
    route = respx.get("https://api.example/x")
    route.side_effect = [httpx.Response(500), httpx.Response(200, json={"ok": True})]
    async with Fetcher(settings) as fetcher:
        assert await fetcher.get_json("https://api.example/x") == (200, {"ok": True})
    assert route.call_count == 2
