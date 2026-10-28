from __future__ import annotations

from ..http import Fetcher
from ..models import CheckResult, Profile
from ..security import is_public_host
from .base import Source, register


@register
class Nostr(Source):
    name = "nostr"
    label = "Nostr (NIP-05)"
    group = "social"
    homepage = "https://nostr.com"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        raw = target.strip().lstrip("@")
        if "@" in raw:
            name, domain = raw.split("@", 1)
        else:
            name, domain = "_", raw
        name = name or "_"
        if not domain or "." not in domain:
            return self.missing(target, "NIP-05 needs name@domain (or a domain for _@domain)")
        if not fetcher.settings.allow_private_targets and not is_public_host(domain, resolve=False):
            return self.blocked(target, "private/loopback NIP-05 domain blocked")
        status, data = await fetcher.get_json(
            f"https://{domain}/.well-known/nostr.json", params={"name": name}
        )
        if status == 200 and isinstance(data, dict):
            pubkey = (data.get("names") or {}).get(name)
            if not pubkey:
                return self.missing(target)
            relays = (data.get("relays") or {}).get(pubkey) or []
            return self.ok(
                target,
                Profile(
                    source=self.name,
                    username=f"{name}@{domain}",
                    url=f"https://{domain}",
                    display_name=f"{name}@{domain}",
                    extra={
                        "nip05": f"{name}@{domain}",
                        "pubkey": pubkey,
                        "relays": relays,
                    },
                ),
            )
        if status == 404:
            return self.missing(target)
        if status in (403, 429):
            return self.blocked(target, f"HTTP {status}: rate limited")
        return self.failed(target, f"HTTP {status}")
