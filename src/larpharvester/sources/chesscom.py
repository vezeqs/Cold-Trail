from __future__ import annotations

from urllib.parse import quote

from ..http import Fetcher
from ..models import CheckResult, Profile
from ..utils import parse_dt
from .base import Source, register


@register
class ChessCom(Source):
    name = "chesscom"
    label = "Chess.com"
    group = "social"
    homepage = "https://www.chess.com"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        status, data = await fetcher.get_json(
            f"https://api.chess.com/pub/player/{quote(target.casefold())}"
        )
        if status == 200 and isinstance(data, dict) and data.get("username"):
            return self.ok(
                target,
                Profile(
                    source=self.name,
                    username=data["username"],
                    url=data.get("url") or f"https://www.chess.com/member/{target}",
                    display_name=data.get("name"),
                    bio=data.get("status"),
                    avatar=data.get("avatar"),
                    created_at=parse_dt(data.get("joined")).isoformat()
                    if parse_dt(data.get("joined"))
                    else None,
                    followers=data.get("followers"),
                    extra={
                        "player_id": data.get("player_id"),
                        "title": data.get("title"),
                        "location": data.get("location"),
                        "country": data.get("country"),
                        "last_online": data.get("last_online"),
                    },
                ),
            )
        if status == 404:
            return self.missing(target)
        if status in (403, 429):
            return self.blocked(target, f"HTTP {status}: rate limited")
        return self.failed(target, f"HTTP {status}")
