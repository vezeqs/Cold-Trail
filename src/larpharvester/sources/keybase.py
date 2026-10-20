from __future__ import annotations

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register

API = "https://keybase.io/_/api/1.0/user/lookup.json"


@register
class Keybase(Source):
    name = "keybase"
    label = "Keybase"
    kind = "email"
    group = "email"
    homepage = "https://keybase.io"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        status, data = await fetcher.get_json(API, params={"emails": target})
        if status == 200 and isinstance(data, dict):
            them = data.get("them") or []
            user = them[0] if them else None
            if isinstance(user, dict):
                basics = user.get("basics") or {}
                profile = user.get("profile") or {}
                username = basics.get("username") or target
                proofs = [
                    {
                        "service": proof.get("proof_type"),
                        "username": proof.get("nametag"),
                        "url": proof.get("proof_url"),
                    }
                    for proof in (user.get("proofs_summary") or {}).get("all") or []
                ]
                pictures = user.get("pictures") or {}
                return self.ok(
                    target,
                    Profile(
                        source=self.name,
                        username=username,
                        url=f"https://keybase.io/{username}",
                        display_name=profile.get("full_name"),
                        bio=profile.get("bio"),
                        avatar=(pictures.get("primary") or {}).get("url"),
                        website=profile.get("website"),
                        extra={
                            "location": profile.get("location"),
                            "proofs": proofs,
                            "uid": basics.get("uid"),
                        },
                    ),
                )
            return self.missing(target)
        if status in (403, 429):
            return self.blocked(target, f"HTTP {status}: rate limited")
        return self.failed(target, f"HTTP {status}")
