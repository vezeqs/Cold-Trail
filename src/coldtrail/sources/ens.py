from __future__ import annotations

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register

RESOLVER = "https://api.ensideas.com/ens/resolve"
AVATAR = "https://metadata.ens.domains/mainnet/avatar"


@register
class ENS(Source):
    name = "ens"
    label = "ENS (.eth)"
    group = "social"
    homepage = "https://app.ens.domains"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        handle = target.strip().lstrip("@").casefold()
        name = handle if handle.endswith(".eth") else f"{handle}.eth"
        status, data = await fetcher.get_json(f"{RESOLVER}/{name}")
        if status == 200 and isinstance(data, dict):
            address = data.get("address")
            if not address:
                return self.missing(target)
            return self.ok(
                target,
                Profile(
                    source=self.name,
                    username=name,
                    url=f"https://app.ens.domains/{name}",
                    display_name=data.get("displayName") or data.get("name") or name,
                    bio=data.get("description"),
                    avatar=f"{AVATAR}/{name}",
                    extra={
                        "ens_name": name,
                        "address": address,
                        "eth_address": address,
                        "resolver": data.get("resolver"),
                    },
                ),
            )
        if status == 404:
            return self.missing(target)
        if status in (403, 429):
            return self.blocked(target, f"HTTP {status}: rate limited")
        return self.failed(target, f"HTTP {status}")
