from __future__ import annotations

import json
import re
from urllib.parse import quote

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register
from .declarative import parse_meta

NEXT_DATA_RE = re.compile(
    r'<script[^>]+id="__NEXT_DATA__"[^>]*>(.*?)</script>',
    re.DOTALL,
)


@register
class Linktree(Source):
    name = "linktree"
    label = "Linktree"
    group = "social"
    homepage = "https://linktr.ee"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        handle = target.strip().lstrip("@")
        url = f"https://linktr.ee/{quote(handle)}"
        status, text = await fetcher.get_text(url)
        if status == 404:
            return self.missing(target)
        if status in (403, 429):
            return self.blocked(target, f"HTTP {status}: rate limited")
        if status != 200:
            return self.failed(target, f"HTTP {status}")

        match = NEXT_DATA_RE.search(text)
        if match:
            try:
                blob = json.loads(match.group(1))
                account = ((blob.get("props") or {}).get("pageProps") or {}).get("account") or {}
                if account.get("username"):
                    uname = str(account["username"])
                    raw_links = account.get("links") or []
                    social_links = account.get("socialLinks") or []
                    accounts = []
                    for item in raw_links:
                        if isinstance(item, dict) and item.get("url"):
                            accounts.append(
                                {"service": item.get("title") or "link", "url": item["url"]}
                            )
                    for item in social_links:
                        if isinstance(item, dict) and item.get("url"):
                            accounts.append(
                                {"service": item.get("type") or "social", "url": item["url"]}
                            )
                    return self.ok(
                        target,
                        Profile(
                            source=self.name,
                            username=uname,
                            url=f"https://linktr.ee/{uname}",
                            display_name=account.get("pageTitle") or uname,
                            bio=account.get("description"),
                            avatar=account.get("profilePictureUrl"),
                            website=accounts[0]["url"] if accounts else None,
                            extra={"accounts": accounts, "link_count": len(accounts)},
                        ),
                    )
            except (ValueError, KeyError, TypeError):
                pass

        meta = parse_meta(text)
        title = (meta.title or "").strip()
        if not title or title.casefold() == "linktree" or "page not found" in title.casefold():
            return self.missing(target)
        return self.ok(
            target,
            Profile(
                source=self.name,
                username=handle,
                url=url,
                display_name=title.split("|")[0].strip() or handle,
                bio=meta.description,
                avatar=meta.image,
            ),
        )
