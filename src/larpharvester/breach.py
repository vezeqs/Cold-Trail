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

import hashlib
from typing import Any
from urllib.parse import quote

from .http import Fetcher, FetchError

HIBP_BREACH_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
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


def sha1_prefix(password: str) -> tuple[str, str]:
    """Split the SHA-1 of a password into (5-char prefix, suffix) for k-anonymity."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return digest[:5], digest[5:]


async def pwned_password(fetcher: Fetcher, password: str) -> dict[str, Any]:
    """Check a password against the Pwned Passwords corpus without revealing it."""
    prefix, suffix = sha1_prefix(password)
    status, text = await _safe_text(
        fetcher,
        PWNED_RANGE_URL.format(prefix=prefix),
        headers={"Accept": "text/plain", "Add-Padding": "true"},
    )
    if status is None:
        return {"status": "error", "detail": text, "count": 0, "prefix": prefix}
    if status != 200:
        return {"status": "error", "detail": f"HTTP {status}", "count": 0, "prefix": prefix}
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
        "prefix": prefix,
    }
