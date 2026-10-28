"""Search-engine providers for web/dork queries."""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from .config import Settings
from .http import Fetcher


def _result(title: Any, url: Any, snippet: Any = "") -> dict[str, str]:
    return {
        "title": str(title or "").strip(),
        "url": str(url or "").strip(),
        "snippet": str(snippet or "").strip(),
    }


async def serper(fetcher: Fetcher, query: str, limit: int, key: str) -> list[dict[str, str]]:
    status, data = await fetcher.post_json(
        "https://google.serper.dev/search",
        json={"q": query, "num": limit},
        headers={"X-API-KEY": key},
    )
    if status != 200 or not isinstance(data, dict):
        return []
    return [
        _result(item.get("title"), item.get("link"), item.get("snippet"))
        for item in data.get("organic") or []
        if isinstance(item, dict)
    ][:limit]


async def brave(fetcher: Fetcher, query: str, limit: int, key: str) -> list[dict[str, str]]:
    status, data = await fetcher.get_json(
        "https://api.search.brave.com/res/v1/web/search",
        params={"q": query, "count": limit},
        headers={"X-Subscription-Token": key, "Accept": "application/json"},
    )
    if status != 200 or not isinstance(data, dict):
        return []
    results = (data.get("web") or {}).get("results") or []
    return [
        _result(item.get("title"), item.get("url"), item.get("description"))
        for item in results
        if isinstance(item, dict)
    ][:limit]


async def searxng(fetcher: Fetcher, query: str, limit: int, base: str) -> list[dict[str, str]]:
    status, data = await fetcher.get_json(
        f"{base.rstrip('/')}/search", params={"q": query, "format": "json"}
    )
    if status != 200 or not isinstance(data, dict):
        return []
    return [
        _result(item.get("title"), item.get("url"), item.get("content"))
        for item in data.get("results") or []
        if isinstance(item, dict)
    ][:limit]


async def duckduckgo(fetcher: Fetcher, query: str, limit: int) -> list[dict[str, str]]:
    status, text = await fetcher.get_text("https://html.duckduckgo.com/html/", params={"q": query})
    if status != 200:
        return []
    soup = BeautifulSoup(text[:500_000], "html.parser")
    results: list[dict[str, str]] = []
    for node in soup.select(".result"):
        link = node.select_one("a.result__a")
        if link is None or not link.get("href"):
            continue
        snippet = node.select_one(".result__snippet")
        results.append(
            _result(
                link.get_text(" ", strip=True),
                urljoin("https://duckduckgo.com", str(link["href"])),
                snippet.get_text(" ", strip=True) if snippet else "",
            )
        )
        if len(results) >= limit:
            break
    return results


async def search(
    fetcher: Fetcher,
    query: str,
    settings: Settings,
    *,
    provider: str = "auto",
    limit: int = 10,
) -> tuple[str, list[dict[str, str]]]:
    provider = provider.casefold()
    if provider == "auto":
        if settings.serper_api_key:
            provider = "serper"
        elif settings.brave_api_key:
            provider = "brave"
        elif settings.searxng_url:
            provider = "searxng"
        else:
            provider = "duckduckgo"
    if provider == "serper" and settings.serper_api_key:
        return provider, await serper(fetcher, query, limit, settings.serper_api_key)
    if provider == "brave" and settings.brave_api_key:
        return provider, await brave(fetcher, query, limit, settings.brave_api_key)
    if provider == "searxng" and settings.searxng_url:
        return provider, await searxng(fetcher, query, limit, settings.searxng_url)
    if provider in {"duckduckgo", "ddg"}:
        return "duckduckgo", await duckduckgo(fetcher, query, limit)
    raise ValueError(f"provider {provider!r} is not configured")
