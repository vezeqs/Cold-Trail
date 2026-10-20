from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime
from urllib.parse import quote

from ..http import Fetcher
from ..models import CheckResult, Post, Profile
from .base import Source, register
from .declarative import parse_meta

HTML_TAG_RE = re.compile(r"<[^>]+>")


def _rss_iso(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value).isoformat()
    except (TypeError, ValueError):
        return value


@register
class Medium(Source):
    name = "medium"
    label = "Medium"
    group = "social"
    homepage = "https://medium.com"
    supports_posts = True

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        handle = target.strip().lstrip("@")
        url = f"https://medium.com/@{quote(handle)}"
        status, text = await fetcher.get_text(url)
        if status == 404:
            return self.missing(target)
        if status in (403, 429):
            return self.blocked(target, f"HTTP {status}: rate limited")
        if status != 200:
            return self.failed(target, f"HTTP {status}")
        meta = parse_meta(text)
        title = (meta.title or "").strip()
        low = title.casefold()
        if not title or low in {"medium", "page not found"} or "404" in low:
            return self.missing(target)
        display = re.sub(r"\s*[-–|]\s*Medium.*$", "", title, flags=re.IGNORECASE).strip()
        display = re.sub(r"^Stories by\s+", "", display, flags=re.IGNORECASE).strip()
        return self.ok(
            target,
            Profile(
                source=self.name,
                username=handle,
                url=url,
                display_name=display or handle,
                bio=meta.description,
                avatar=meta.image,
            ),
        )

    async def posts(
        self,
        fetcher: Fetcher,
        target: str,
        limit: int,
        *,
        since: str | None = None,
    ) -> list[Post]:
        handle = target.strip().lstrip("@")
        status, text = await fetcher.get_text(f"https://medium.com/feed/@{quote(handle)}")
        if status != 200 or "<rss" not in text[:500]:
            return []
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return []
        items: list[Post] = []
        for item in root.findall("./channel/item"):
            title = (item.findtext("title") or "").strip()
            link = (item.findtext("link") or "").strip()
            guid = (item.findtext("guid") or link or title).strip()
            pub = _rss_iso(item.findtext("pubDate"))
            if since and pub and pub < since:
                break
            desc = item.findtext("description") or ""
            clean_desc = HTML_TAG_RE.sub(" ", desc)
            clean_desc = " ".join(clean_desc.split())[:400]
            body = f"{title} — {clean_desc}" if clean_desc else title
            items.append(
                Post(
                    source=self.name,
                    username=handle,
                    post_id=guid,
                    url=link or f"https://medium.com/@{handle}",
                    created_at=pub,
                    text=body,
                )
            )
            if len(items) >= limit:
                break
        return items
