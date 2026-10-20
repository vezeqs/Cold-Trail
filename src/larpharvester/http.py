from __future__ import annotations

import asyncio
import json
import random
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import quote_plus, urlsplit
from urllib.robotparser import RobotFileParser

import httpx

from .config import Settings
from .utils import now_iso

if TYPE_CHECKING:
    from .store import Store

RETRIES = 2
BACKOFF = 1.0
CIRCUIT_THRESHOLD = 5
CIRCUIT_SECONDS = 60.0
MAX_BODY = 2_000_000

HARD_MARKERS = (
    "just a moment",
    "cf-challenge",
    "cf-turnstile",
    "attention required",
    "enable javascript and cookies",
    "checking your browser",
    "ddos-guard",
    "verify you are human",
    "are you a robot",
    "access denied",
    "perimeterx",
    "px-captcha",
    "datadome",
    "incapsula incident",
    "_incapsula_resource",
    "akamai reference",
    "sucuri website firewall",
)

WAF_HEADER_MARKERS = (
    ("cf-mitigated", "challenge"),
    ("x-datadome", "protected"),
    ("x-sucuri-block", ""),
)


class FetchError(Exception):
    """A request could not be completed (network error, retries exhausted, no recording)."""


class BlockedError(FetchError):
    """The source actively refused or challenged the request."""


class BudgetExceeded(FetchError):
    """The per-run request budget was exhausted."""


@dataclass(slots=True)
class Fetched:
    status: int
    text: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    json: Any = None
    content: bytes = b""
    from_cache: bool = False


class Fetcher:
    """Shared async HTTP client: concurrency cap, per-host pacing, caching, retries,
    circuit breaking, optional proxy/Tor, raw capture and replay."""
    def __init__(
        self,
        settings: Settings,
        store: Store | None = None,
        run_id: int | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.run_id = run_id
        proxy = "socks5://127.0.0.1:9050" if settings.tor else settings.proxy
        self._client = httpx.AsyncClient(
            timeout=settings.timeout,
            follow_redirects=True,
            proxy=proxy or None,
            limits=httpx.Limits(
                max_connections=max(8, settings.concurrency * 2),
                max_keepalive_connections=max(4, settings.concurrency),
            ),
            headers={
                "User-Agent": settings.user_agent,
                "Accept-Language": "en-US,en;q=0.9",
            },
        )
        self._sem = asyncio.Semaphore(max(1, settings.concurrency))
        self._hosts: dict[str, dict[str, Any]] = {}
        self._robots: dict[str, RobotFileParser] = {}
        self.requests = 0
        self._req_lock = asyncio.Lock()

    async def __aenter__(self) -> Fetcher:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    # -- public API ---------------------------------------------------------

    async def get(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Fetched:
        return await self._request("GET", url, params=params, headers=headers)

    async def post(
        self,
        url: str,
        *,
        data: dict[str, Any] | None = None,
        json: Any = None,
        headers: dict[str, str] | None = None,
    ) -> Fetched:
        return await self._request("POST", url, data=data, json=json, headers=headers)

    async def get_json(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, Any]:
        response = await self.get(
            url,
            params=params,
            headers={"Accept": "application/json", **(headers or {})},
        )
        if response.json is not None:
            return response.status, response.json
        if response.status in (204, 304) or not response.text.strip():
            return response.status, None
        if "html" in response.headers.get("content-type", "") and response.status == 200:
            raise BlockedError(f"non-JSON response from {url} (bot wall or changed API)")
        return response.status, None

    async def get_text(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, str]:
        response = await self.get(
            url,
            params=params,
            headers={
                "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
                **(headers or {}),
            },
        )
        return response.status, response.text

    async def post_json(
        self,
        url: str,
        *,
        data: dict[str, Any] | None = None,
        json: Any = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, Any]:
        response = await self.post(
            url,
            data=data,
            json=json,
            headers={"Accept": "application/json", **(headers or {})},
        )
        return response.status, response.json

    # -- internals ----------------------------------------------------------

    async def _request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        data: dict[str, Any] | None = None,
        json: Any = None,
    ) -> Fetched:
        key = _cache_key(url, params)
        host = urlsplit(key).netloc

        if self.settings.replay:
            return self._replay(key)

        cached = self._cache_get(key) if method == "GET" else None
        if cached is not None:
            return cached
        stale = self._cache_row(key) if method == "GET" and cached is None else None

        if not await self._allowed(key):
            raise BlockedError(f"robots.txt disallows {key}")

        state = self._host_state(host)
        delay = BACKOFF
        last_error: Exception | None = None

        for attempt in range(RETRIES + 1):
            if time.monotonic() < state["open_until"]:
                raise FetchError(f"circuit open for {host} after repeated failures")
            async with self._req_lock:
                if self.settings.max_requests and self.requests >= self.settings.max_requests:
                    raise BudgetExceeded(
                        f"request budget of {self.settings.max_requests} exhausted"
                    )
                self.requests += 1
            await self._pace(host, state)
            request_headers = dict(headers or {})
            etag = (stale or {}).get("etag")
            if etag:
                request_headers.setdefault("If-None-Match", etag)
            try:
                async with self._sem:
                    response = await self._client.request(
                        method, url, params=params, headers=request_headers, data=data, json=json
                    )
            except httpx.HTTPError as exc:
                last_error = exc
                self._record_failure(state)
                if attempt < RETRIES:
                    await asyncio.sleep(delay)
                    delay *= 2
                    continue
                raise FetchError(f"{type(exc).__name__}: {exc}") from exc

            if response.status_code == 304 and stale is not None:
                return self._from_cache(stale, key)

            if response.status_code == 429 or response.status_code >= 500:
                if attempt < RETRIES:
                    retry_after = response.headers.get("Retry-After", "")
                    wait = float(retry_after) if retry_after.isdigit() else delay
                    await asyncio.sleep(wait)
                    delay *= 2
                    continue
                self._record_failure(state)
                raise BlockedError(
                    f"HTTP {response.status_code} from {host} after {RETRIES + 1} attempts"
                )

            state["fails"] = 0
            fetched = self._build(response, key)
            if self.settings.keep_raw and self.store is not None:
                self.store.raw_put(key, fetched.status, response.content, self.run_id)
            if method == "GET" and response.status_code == 200:
                self._cache_put(key, response)
            if _looks_blocked(fetched):
                raise BlockedError(f"bot wall / access denied on {host} (HTTP {fetched.status})")
            return fetched

        raise FetchError(f"request to {url} failed: {last_error}")

    def _build(self, response: httpx.Response, key: str) -> Fetched:
        content_type = response.headers.get("content-type", "")
        payload: Any = None
        if response.content and ("json" in content_type or response.text[:1] in ("{", "[")):
            try:
                payload = response.json()
            except ValueError:
                payload = None
        return Fetched(
            status=response.status_code,
            text=response.text[:MAX_BODY],
            url=str(response.url) if response.url else key,
            headers=dict(response.headers),
            json=payload,
            content=response.content,
        )

    def _host_state(self, host: str) -> dict[str, Any]:
        return self._hosts.setdefault(
            host, {"lock": asyncio.Lock(), "last": 0.0, "fails": 0, "open_until": 0.0}
        )

    async def _pace(self, host: str, state: dict[str, Any]) -> None:
        rps = self.settings.requests_per_second
        wait = 0.0
        async with state["lock"]:
            if rps > 0:
                now = time.monotonic()
                earliest = state["last"] + (1.0 / rps)
                if earliest > now:
                    wait = earliest - now
                    state["last"] = earliest
                else:
                    state["last"] = now
            else:
                state["last"] = time.monotonic()
        if wait > 0:
            await asyncio.sleep(wait + random.uniform(0, max(0.0, self.settings.jitter)))

    @staticmethod
    def _record_failure(state: dict[str, Any]) -> None:
        state["fails"] += 1
        if state["fails"] >= CIRCUIT_THRESHOLD:
            state["open_until"] = time.monotonic() + CIRCUIT_SECONDS
            state["fails"] = 0

    async def _allowed(self, url: str) -> bool:
        if not self.settings.respect_robots:
            return True
        host = urlsplit(url).netloc
        parser = self._robots.get(host)
        if parser is None:
            parser = RobotFileParser()
            try:
                parser.parse(await self._fetch_robots(host))
            except FetchError:
                parser.parse([])
            self._robots[host] = parser
        return parser.can_fetch(self.settings.user_agent, url)

    async def _fetch_robots(self, host: str) -> list[str]:
        """Fetch robots.txt through the normal pacing/budget accounting."""
        state = self._host_state(host)
        async with self._req_lock:
            if self.settings.max_requests and self.requests >= self.settings.max_requests:
                raise BudgetExceeded(f"request budget of {self.settings.max_requests} exhausted")
            self.requests += 1
        await self._pace(host, state)
        try:
            async with self._sem:
                response = await self._client.get(f"https://{host}/robots.txt")
        except httpx.HTTPError as exc:
            self._record_failure(state)
            raise FetchError(f"{type(exc).__name__}: {exc}") from exc
        if response.status_code != 200:
            return []
        return response.text.splitlines()

    def _cache_row(self, key: str) -> dict[str, Any] | None:
        if not self.settings.cache_ttl or self.store is None:
            return None
        return self.store.cache_get(key)

    def _cache_get(self, key: str) -> Fetched | None:
        row = self._cache_row(key)
        if row is None:
            return None
        try:
            fetched = datetime.fromisoformat(row["fetched_at"])
            if fetched.tzinfo is None:
                fetched = fetched.replace(tzinfo=UTC)
            age = (datetime.now(UTC) - fetched).total_seconds()
        except (KeyError, TypeError, ValueError):
            return None
        if age > self.settings.cache_ttl:
            return None
        return self._from_cache(row, key)

    @staticmethod
    def _from_cache(row: dict[str, Any], key: str) -> Fetched:
        body = row["body"]
        text = body.decode("utf-8", "replace")
        try:
            payload = json.loads(text)
        except ValueError:
            payload = None
        headers = {"content-type": row.get("content_type") or ""}
        final_url = row.get("final_url") or key
        return Fetched(
            status=row["status"],
            text=text,
            url=final_url,
            headers=headers,
            json=payload,
            content=body,
            from_cache=True,
        )

    def _cache_put(self, key: str, response: httpx.Response) -> None:
        if not self.settings.cache_ttl or self.store is None:
            return
        self.store.cache_put(
            key,
            response.status_code,
            response.content,
            response.headers.get("content-type", ""),
            response.headers.get("etag", ""),
            response.headers.get("last-modified", ""),
            now_iso(),
            final_url=str(response.url) if response.url else key,
        )

    def _replay(self, key: str) -> Fetched:
        if self.store is None:
            raise FetchError("replay requires a store")
        row = self.store.raw_get(key)
        if row is None:
            raise FetchError(f"no recording for {key}")
        text = row["body"].decode("utf-8", "replace")
        try:
            payload = json.loads(text)
        except ValueError:
            payload = None
        return Fetched(status=row["status"], text=text, url=key, json=payload, content=row["body"])


def _cache_key(url: str, params: dict[str, Any] | None) -> str:
    if not params:
        return url
    ordered = sorted((str(k), str(v)) for k, v in params.items() if v is not None)
    query = "&".join(f"{quote_plus(k)}={quote_plus(v)}" for k, v in ordered)
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}{query}"


def _looks_blocked(response: Fetched) -> bool:
    if response.status == 304:
        return False
    low_headers = {k.lower(): v.lower() for k, v in response.headers.items()}
    for header, expected in WAF_HEADER_MARKERS:
        if header in low_headers and (not expected or expected in low_headers[header]):
            return True
    content_type = low_headers.get("content-type", "")
    low = response.text[:5000].lower()
    if response.status in (401, 403, 407, 429, 503):
        return "html" in content_type or any(marker in low for marker in HARD_MARKERS)
    if response.status == 200 and "html" in content_type:
        return any(marker in low for marker in HARD_MARKERS)
    return False


@asynccontextmanager
async def shared_fetcher(
    settings: Settings,
    store: Store | None = None,
    fetcher: Fetcher | None = None,
    run_id: int | None = None,
):
    """Reuse a caller-provided Fetcher, or open (and close) a new one.

    Multi-phase operations (watch cycles, pivot + harvest) must share a single
    Fetcher so per-run budgets, host pacing, and circuit state apply globally.
    """
    if fetcher is not None:
        yield fetcher
        return
    async with Fetcher(settings, store=store, run_id=run_id) as owned:
        yield owned
