from __future__ import annotations

from urllib.parse import quote

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register


@register
class Matrix(Source):
    name = "matrix"
    label = "Matrix"
    group = "social"
    homepage = "https://matrix.org"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        raw = target.strip()
        if raw.startswith("@") and ":" in raw:
            localpart, server = raw[1:].split(":", 1)
        elif ":" in raw and "@" not in raw:
            localpart, server = raw.split(":", 1)
        else:
            localpart = raw.lstrip("@")
            server = "matrix.org"
        mxid = f"@{localpart}:{server}"
        status, data = await fetcher.get_json(
            f"https://matrix-client.matrix.org/_matrix/client/v3/profile/{quote(mxid, safe='')}"
        )
        if status == 200 and isinstance(data, dict):
            display = data.get("displayname")
            avatar_mxc = data.get("avatar_url")
            if not display and not avatar_mxc:
                return self.missing(target)
            avatar = None
            if isinstance(avatar_mxc, str) and avatar_mxc.startswith("mxc://"):
                parts = avatar_mxc.removeprefix("mxc://").split("/", 1)
                if len(parts) == 2:
                    avatar = (
                        f"https://matrix-client.matrix.org/_matrix/media/v3/download/"
                        f"{parts[0]}/{parts[1]}"
                    )
            return self.ok(
                target,
                Profile(
                    source=self.name,
                    username=localpart,
                    url=f"https://matrix.to/#/{mxid}",
                    display_name=display or localpart,
                    avatar=avatar,
                    extra={"mxid": mxid, "homeserver": server, "avatar_mxc": avatar_mxc},
                ),
            )
        if status in (400, 404):
            return self.missing(target)
        if status in (403, 429):
            return self.blocked(target, f"HTTP {status}: rate limited")
        return self.failed(target, f"HTTP {status}")
