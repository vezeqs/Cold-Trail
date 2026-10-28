from __future__ import annotations

import json
import re
from urllib.parse import quote

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register
from .declarative import parse_meta

SIGI_RE = re.compile(
    r'<script[^>]+id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>(.*?)</script>',
    re.DOTALL,
)


@register
class TikTok(Source):
    name = "tiktok"
    label = "TikTok"
    group = "social"
    homepage = "https://www.tiktok.com"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        handle = target.strip().lstrip("@")
        url = f"https://www.tiktok.com/@{quote(handle)}"
        status, text = await fetcher.get_text(url)
        if status == 404:
            return self.missing(target)
        if status in (403, 429):
            return self.blocked(target, f"HTTP {status}: rate limited")
        if status != 200:
            return self.failed(target, f"HTTP {status}")

        match = SIGI_RE.search(text)
        if match:
            try:
                blob = json.loads(match.group(1))
                scope = blob.get("__DEFAULT_SCOPE__") or {}
                detail = scope.get("webapp.user-detail") or {}
                user_info = detail.get("userInfo") or {}
                user = user_info.get("user") or {}
                stats = user_info.get("stats") or {}
                if user.get("uniqueId"):
                    uid = str(user["uniqueId"])
                    return self.ok(
                        target,
                        Profile(
                            source=self.name,
                            username=uid,
                            url=f"https://www.tiktok.com/@{uid}",
                            display_name=user.get("nickname") or uid,
                            bio=user.get("signature") or None,
                            avatar=user.get("avatarLarger") or user.get("avatarMedium"),
                            website=(user.get("bioLink") or {}).get("link")
                            if isinstance(user.get("bioLink"), dict)
                            else None,
                            followers=stats.get("followerCount"),
                            extra={
                                "id": user.get("id"),
                                "verified": bool(user.get("verified")),
                                "following": stats.get("followingCount"),
                                "heart_count": stats.get("heartCount"),
                                "video_count": stats.get("videoCount"),
                            },
                        ),
                    )
                if detail.get("statusCode") in (10202, 10221, 10222):
                    return self.missing(target)
            except (ValueError, KeyError, TypeError):
                pass

        meta = parse_meta(text)
        title = (meta.title or "").strip()
        if not title or "tiktok - make your day" in title.casefold():
            return self.missing(target)
        if f"@{handle.casefold()}" not in title.casefold() and (
            handle.casefold() not in text[:8000].casefold()
        ):
            return self.missing(target)
        return self.ok(
            target,
            Profile(
                source=self.name,
                username=handle,
                url=url,
                display_name=title.split("(@")[0].strip() or handle,
                bio=meta.description,
                avatar=meta.image,
            ),
        )
