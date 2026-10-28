from __future__ import annotations

from urllib.parse import unquote

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register


@register
class PGP(Source):
    name = "pgp"
    label = "OpenPGP keyservers"
    kind = "email"
    group = "email"
    homepage = "https://keys.openpgp.org"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        status, text = await fetcher.get_text(
            "https://keyserver.ubuntu.com/pks/lookup",
            params={"search": target, "op": "index", "options": "mr"},
        )
        if status != 200:
            return self.missing(target) if status == 404 else self.failed(target, f"HTTP {status}")
        uids: list[str] = []
        for line in text.splitlines():
            if not line.startswith("uid:"):
                continue
            parts = line.split(":", 4)
            if len(parts) > 1:
                uid = unquote(parts[1]).strip()
                if uid and uid not in uids:
                    uids.append(uid)
        if not uids:
            return self.missing(target)
        return self.ok(
            target,
            Profile(
                source=self.name,
                username=target,
                url=f"https://keyserver.ubuntu.com/pks/lookup?search={target}&op=index",
                display_name=uids[0],
                bio="; ".join(uids),
                extra={"uids": uids, "keyserver": "keyserver.ubuntu.com"},
            ),
        )
