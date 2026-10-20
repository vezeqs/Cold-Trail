from __future__ import annotations

import hashlib
import html
import re
from datetime import UTC, datetime
from urllib.parse import urlsplit

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def strip_html(text: str | None) -> str | None:
    """Turn a snippet of HTML (Mastodon notes, HN about fields) into plain text."""
    if not text:
        return None
    cleaned = _WS_RE.sub(" ", html.unescape(_TAG_RE.sub(" ", text))).strip()
    return cleaned or None


def norm(text: str | None) -> str:
    """Normalize free text for comparison."""
    if not text:
        return ""
    return _WS_RE.sub(" ", strip_html(text) or "").strip().casefold()


COSMETIC_QUERY_PARAMS = {
    "size",
    "s",
    "width",
    "height",
    "w",
    "h",
    "v",
    "version",
    "timestamp",
    "t",
    "quality",
    "q",
    "format",
    "fm",
    "auto",
    "fit",
    "crop",
}


def norm_url(url: str | None, *, preserve_query: bool = False) -> str:
    """Normalize a URL so cosmetic differences don't defeat correlation."""
    if not url:
        return ""
    parts = urlsplit(url.strip())
    host = parts.netloc.casefold().removeprefix("www.")
    path = parts.path.rstrip("/").casefold()
    if preserve_query and parts.query:
        # Strip cosmetic resize / cache-busting params, but keep identifying query params
        kept = []
        for pair in parts.query.split("&"):
            if not pair:
                continue
            k = pair.split("=", 1)[0].casefold()
            if k not in COSMETIC_QUERY_PARAMS:
                kept.append(pair)
        if kept:
            return f"{host}{path}?{'&'.join(kept)}" if host else ""
        return f"{host}{path}" if host else ""
    return f"{host}{path}" if host else ""


def host_of(url: str | None) -> str:
    if not url:
        return ""
    return urlsplit(url.strip()).netloc.casefold().removeprefix("www.")


def parse_dt(value: object) -> datetime | None:
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, UTC)
        except (OverflowError, OSError, ValueError):
            return None
    if not value:
        return None
    text = str(value).strip()
    if text.isdigit():
        return parse_dt(int(text))
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def days_between(left: object, right: object) -> float | None:
    a, b = parse_dt(left), parse_dt(right)
    if a is None or b is None:
        return None
    return abs((a - b).total_seconds()) / 86_400


def is_after(value: object, since: object) -> bool:
    if not since:
        return True
    a, b = parse_dt(value), parse_dt(since)
    if a is None or b is None:
        return True
    return a >= b


def hamming_hex(left: str, right: str) -> int:
    try:
        return (int(left, 16) ^ int(right, 16)).bit_count()
    except (TypeError, ValueError):
        return 64


def short_key(text: str, length: int = 12) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:length]


def dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        key = value.casefold()
        if key not in seen:
            seen.add(key)
            out.append(value)
    return out
