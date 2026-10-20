from __future__ import annotations

from typing import Any

from .http import Fetcher


async def cdx(fetcher: Fetcher, url: str, limit: int = 50) -> list[dict[str, Any]]:
    """List Wayback Machine captures for a URL (CDX API)."""
    status, data = await fetcher.get_json(
        "https://web.archive.org/cdx/search/cdx",
        params={
            "url": url,
            "output": "json",
            "limit": limit,
            "filter": "statuscode:200",
            "collapse": "digest",
            "fl": "timestamp,original,statuscode,mimetype,digest,length",
        },
    )
    if status != 200 or not isinstance(data, list) or len(data) < 2:
        return []
    header = data[0]
    return [dict(zip(header, row, strict=False)) for row in data[1:]]


async def snapshot(fetcher: Fetcher, timestamp: str, url: str) -> str | None:
    """Fetch the raw archived body for one capture."""
    status, text = await fetcher.get_text(f"https://web.archive.org/web/{timestamp}id_/{url}")
    return text if status == 200 and text else None


async def recover_profile_snapshots(
    fetcher: Fetcher, url: str, limit: int = 5
) -> list[dict[str, Any]]:
    """Recover historical page metadata (title/description/image) from Wayback captures."""
    from .sources.declarative import parse_meta

    captures = await cdx(fetcher, url, limit=max(limit * 4, 20))
    if not captures:
        return []
    seen: set[tuple[str | None, str | None]] = set()
    out: list[dict[str, Any]] = []
    for capture in reversed(captures):
        timestamp = str(capture.get("timestamp") or "")
        original = str(capture.get("original") or url)
        if not timestamp:
            continue
        try:
            status, text = await fetcher.get_text(
                f"https://web.archive.org/web/{timestamp}id_/{original}"
            )
        except Exception:
            continue
        if status != 200 or not text:
            continue
        meta = parse_meta(text)
        key = (meta.title, meta.description)
        if key in seen or (not meta.title and not meta.description):
            continue
        seen.add(key)
        out.append(
            {
                "timestamp": timestamp,
                "url": original,
                "title": meta.title,
                "description": meta.description,
                "image": meta.image,
            }
        )
        if len(out) >= limit:
            break
    return out
