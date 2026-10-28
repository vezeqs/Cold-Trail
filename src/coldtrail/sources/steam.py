from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from urllib.parse import quote

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register


@register
class Steam(Source):
    name = "steam"
    label = "Steam"
    group = "social"
    homepage = "https://steamcommunity.com"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        status, text = await fetcher.get_text(
            f"https://steamcommunity.com/id/{quote(target)}", params={"xml": "1"}
        )
        if status != 200:
            return self.missing(target) if status == 404 else self.failed(target, f"HTTP {status}")
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return self.failed(target, "unparseable XML profile")
        if root.findtext("error"):
            return self.missing(target, root.findtext("error"))
        steam_id = root.findtext("steamID")
        if not steam_id:
            return self.missing(target)
        created = root.findtext("timecreated")
        if created and created.isdigit():
            created = datetime.fromtimestamp(int(created), UTC).isoformat()
        return self.ok(
            target,
            Profile(
                source=self.name,
                username=steam_id,
                url=f"https://steamcommunity.com/id/{target}",
                display_name=root.findtext("steamID"),
                bio=root.findtext("summary"),
                avatar=root.findtext("avatarFull"),
                created_at=created,
                extra={
                    "steamid64": root.findtext("steamID64"),
                    "realname": root.findtext("realname"),
                    "location": root.findtext("location"),
                    "state": root.findtext("stateMessage"),
                    "privacy": root.findtext("privacyState"),
                },
            ),
        )
