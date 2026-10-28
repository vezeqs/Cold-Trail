from __future__ import annotations

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register

UNDELIVERABLE = {"invalid", "undeliverable"}


@register
class Hunter(Source):
    name = "hunter"
    label = "Hunter.io"
    kind = "email"
    group = "email"
    homepage = "https://hunter.io"
    requires_auth = True

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        key = fetcher.settings.hunter_api_key
        if not key:
            return self.blocked(target, "HUNTER_API_KEY is not configured")
        status, data = await fetcher.get_json(
            "https://api.hunter.io/v2/email-verifier",
            params={"email": target, "api_key": key},
        )
        if status == 404:
            return self.missing(target, "email not found")
        if status in (401, 403):
            return self.blocked(target, "Hunter rejected the API key")
        if status == 429:
            return self.blocked(target, "rate limited by Hunter")
        if status != 200 or not isinstance(data, dict):
            return self.failed(target, f"HTTP {status}")
        result = data.get("data") or {}
        if not isinstance(result, dict):
            return self.failed(target, "unexpected Hunter payload")
        verdict = str(result.get("status") or result.get("result") or "unknown").casefold()
        if verdict in UNDELIVERABLE:
            return self.missing(target, f"email {verdict}")
        score = result.get("score")
        sources = result.get("sources") or []
        return self.ok(
            target,
            Profile(
                source=self.name,
                username=target,
                url="https://hunter.io/email-verifier",
                bio=f"email {verdict}" + (f" (confidence {score})" if score is not None else ""),
                extra={
                    "status": verdict,
                    "score": score,
                    "disposable": result.get("disposable"),
                    "webmail": result.get("webmail"),
                    "accept_all": result.get("accept_all"),
                    "mx_records": result.get("mx_records"),
                    "smtp_check": result.get("smtp_check"),
                    "sources": [
                        {
                            "domain": item.get("domain"),
                            "uri": item.get("uri"),
                        }
                        for item in sources
                        if isinstance(item, dict)
                    ][:20],
                },
            ),
        )
