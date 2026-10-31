from __future__ import annotations

import base64
import contextlib
import hashlib
import html
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def ssh_fingerprint(key_line: str | None) -> str | None:
    """Compute the OpenSSH SHA256 fingerprint of an authorized_keys line."""
    if not key_line:
        return None
    parts = key_line.strip().split()
    if len(parts) < 2:
        return None
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (ValueError, TypeError):
        return None
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return f"SHA256:{digest}"


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def sensitive_cache_key(prefix: str, value: str) -> str:
    """Stable cache/raw key for a sensitive identifier (email, phone, token).

    The identifier itself never enters ``http_cache``/``raw`` URLs, so a local
    database leak does not expose which addresses were investigated.
    """
    digest = hashlib.sha256(value.strip().casefold().encode("utf-8")).hexdigest()
    return f"{prefix}:{digest}"


def write_private(path: Path, data: bytes) -> None:
    """Write an export/evidence copy with owner-only permissions."""
    destination = Path(path).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    with contextlib.suppress(OSError):
        os.chmod(destination, 0o600)


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


def epoch_seconds(value: object) -> int | None:
    parsed = parse_dt(value)
    return int(parsed.timestamp()) if parsed is not None else None


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


def is_sha256(value: object) -> bool:
    """True for a lowercase 64-character hex digest (evidence blob names)."""
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def json_loads(value: object, default: object) -> object:
    """Parse stored JSON without letting one corrupt row crash a query."""
    try:
        return json.loads(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def redact_url_credentials(value: str | None) -> str | None:
    """Strip ``user:password@`` from a URL before it reaches output or logs."""
    if not value:
        return value
    parts = urlsplit(value)
    if not parts.username and not parts.password:
        return value
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    port = f":{parts.port}" if parts.port else ""
    netloc = f"[redacted]@{host}{port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        key = value.casefold()
        if key not in seen:
            seen.add(key)
            out.append(value)
    return out
