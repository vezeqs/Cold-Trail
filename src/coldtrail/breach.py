"""Breach-exposure auditing (defensive).

Two checks, both standard industry APIs:

- ``hibp_breaches``: which breaches an email address appears in (HIBP, keyed).
- ``pwned_password``: whether a *user-supplied* password appears in the Pwned
  Passwords corpus, via SHA-1 k-anonymity. Only the first five hex characters
  of the hash ever leave the machine; the full hash and the password never do.

This module deliberately has no capability to retrieve, dump, or crack
credentials. It answers "was this exposed?" — never "what is it?".
"""

from __future__ import annotations

import asyncio
import hashlib
from typing import Any
from urllib.parse import quote

from .http import Fetcher, FetchError
from .utils import sensitive_cache_key

HIBP_BREACH_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
HUDSONROCK_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email"
LEAKCHECK_URL = "https://leakcheck.io/api/public"
PWNED_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"


async def _safe_json(fetcher: Fetcher, url: str, **kwargs: Any) -> tuple[int | None, Any]:
    try:
        return await fetcher.get_json(url, **kwargs)
    except FetchError as exc:
        return None, str(exc)


async def _safe_text(fetcher: Fetcher, url: str, **kwargs: Any) -> tuple[int | None, str]:
    try:
        return await fetcher.get_text(url, **kwargs)
    except FetchError as exc:
        return None, str(exc)


async def hibp_breaches(fetcher: Fetcher, email: str) -> dict[str, Any]:
    """Return breach metadata for an email address."""
    key = fetcher.settings.hibp_api_key
    if not key:
        return {
            "status": "blocked",
            "detail": "HIBP_API_KEY is not configured",
            "breaches": [],
        }
    status, data = await _safe_json(
        fetcher,
        HIBP_BREACH_URL.format(email=quote(email)),
        params={"truncateResponse": "false"},
        headers={"hibp-api-key": key},
        cache_key=sensitive_cache_key("hibp", email),
    )
    if status is None:
        return {"status": "error", "detail": data, "breaches": []}
    if status == 200 and isinstance(data, list):
        breaches = [
            {
                "name": item.get("Name"),
                "title": item.get("Title"),
                "date": item.get("BreachDate"),
                "pwn_count": item.get("PwnCount"),
                "data_classes": item.get("DataClasses") or [],
                "domain": item.get("Domain"),
                "verified": bool(item.get("IsVerified")),
                "sensitive": bool(item.get("IsSensitive")),
            }
            for item in data
        ]
        return {
            "status": "found",
            "detail": f"appears in {len(breaches)} breach(es)",
            "breaches": breaches,
        }
    if status == 404:
        return {"status": "none", "detail": "not found in any breach", "breaches": []}
    if status == 401:
        return {"status": "blocked", "detail": "HIBP rejected the API key", "breaches": []}
    if status in (403, 429):
        return {
            "status": "blocked",
            "detail": f"HTTP {status}: rate limited",
            "breaches": [],
        }
    return {"status": "error", "detail": f"HTTP {status}", "breaches": []}


async def hudsonrock_exposure(fetcher: Fetcher, email: str) -> dict[str, Any]:
    """Query HudsonRock Cavalier public telemetry for infostealer exposure metadata."""
    status, data = await _safe_json(
        fetcher,
        HUDSONROCK_URL,
        params={"email": email.strip()},
        cache_key=sensitive_cache_key("hudsonrock", email),
    )
    if status is None:
        return {"status": "error", "detail": data, "stealers": []}
    if status == 200 and isinstance(data, dict):
        stealers = data.get("stealers") or []
        return {
            "status": "found" if stealers else "none",
            "detail": (
                f"{len(stealers)} infostealer record(s)"
                if stealers
                else "not found in infostealer telemetry"
            ),
            "stealers": stealers[:25],
        }
    if status == 404:
        return {"status": "none", "detail": "not found", "stealers": []}
    if status in (401, 403, 429):
        return {"status": "blocked", "detail": f"HTTP {status}: rate limited", "stealers": []}
    return {"status": "error", "detail": f"HTTP {status}", "stealers": []}


async def leakcheck_public(fetcher: Fetcher, email: str) -> dict[str, Any]:
    """Query LeakCheck's unauthenticated public API for breach source names & fields."""
    status, data = await _safe_json(
        fetcher,
        LEAKCHECK_URL,
        params={"check": email.strip()},
        cache_key=sensitive_cache_key("leakcheck", email),
    )
    if status is None:
        return {"status": "error", "detail": data, "sources": [], "fields": []}
    if status == 200 and isinstance(data, dict):
        found = int(data.get("found") or 0)
        if not data.get("success") or found <= 0:
            return {"status": "none", "detail": "not found", "sources": [], "fields": []}
        return {
            "status": "found",
            "detail": f"appears in {found} record(s)",
            "found": found,
            "fields": data.get("fields") or [],
            "sources": data.get("sources") or [],
        }
    if status == 404:
        return {"status": "none", "detail": "not found", "sources": [], "fields": []}
    if status in (401, 403, 429):
        return {
            "status": "blocked",
            "detail": f"HTTP {status}: rate limited",
            "sources": [],
            "fields": [],
        }
    return {"status": "error", "detail": f"HTTP {status}", "sources": [], "fields": []}


async def full_breach_audit(fetcher: Fetcher, email: str) -> dict[str, Any]:
    """Run HIBP + HudsonRock + LeakCheck concurrently for an email address."""
    hibp, hr, lc = await asyncio.gather(
        hibp_breaches(fetcher, email),
        hudsonrock_exposure(fetcher, email),
        leakcheck_public(fetcher, email),
    )
    any_found = any(r.get("status") == "found" for r in (hibp, hr, lc))
    return {
        "email": email,
        "status": "found" if any_found else hibp.get("status", "none"),
        "hibp": hibp,
        "hudsonrock": hr,
        "leakcheck": lc,
    }


def sha1_prefix(password: str) -> tuple[str, str]:
    """Split the SHA-1 of a password into (5-char prefix, suffix) for k-anonymity."""
    digest = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
    return digest[:5], digest[5:]


async def pwned_password(fetcher: Fetcher, password: str) -> dict[str, Any]:
    """Check a password against the Pwned Passwords corpus without revealing it."""
    prefix, suffix = sha1_prefix(password)
    status, text = await _safe_text(
        fetcher,
        PWNED_RANGE_URL.format(prefix=prefix),
        headers={"Accept": "text/plain", "Add-Padding": "true"},
        # The prefix is the only part of the hash that leaves the machine; keep
        # it out of the local cache/raw key and any error detail as well.
        cache_key=sensitive_cache_key("pwned", password),
    )
    if status is None:
        return {"status": "error", "detail": text.replace(prefix, "[redacted]"), "count": 0}
    if status != 200:
        return {"status": "error", "detail": f"HTTP {status}", "count": 0}
    count = 0
    for line in text.splitlines():
        part, _, value = line.partition(":")
        if part.strip().upper() != suffix:
            continue
        try:
            count = int(value.strip())
        except ValueError:
            count = 0
        break
    return {
        "status": "pwned" if count else "clean",
        "detail": (
            f"seen {count} time(s) in breach corpora" if count else "not found in any breach corpus"
        ),
        "count": count,
    }
