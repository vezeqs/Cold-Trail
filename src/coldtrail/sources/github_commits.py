from __future__ import annotations

from ..http import Fetcher
from ..models import CheckResult, Profile
from ..utils import sensitive_cache_key
from .base import Source, register

API = "https://api.github.com"


@register
class GitHubCommits(Source):
    name = "github-commits"
    label = "GitHub commit authors"
    kind = "email"
    group = "email"
    homepage = "https://github.com"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        headers = {
            "Accept": "application/vnd.github.cloak-preview+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if fetcher.settings.github_token:
            headers["Authorization"] = f"Bearer {fetcher.settings.github_token}"
        status, data = await fetcher.get_json(
            f"{API}/search/commits",
            params={"q": f"author-email:{target}", "per_page": 20},
            headers=headers,
            cache_key=sensitive_cache_key("github-commits", target),
        )
        if status == 200 and isinstance(data, dict):
            total = int(data.get("total_count") or 0)
            items = data.get("items") or []
            if total == 0 or not items:
                return self.missing(target)
            logins = [
                (item.get("author") or {}).get("login")
                for item in items
                if (item.get("author") or {}).get("login")
            ]
            repos = list(
                dict.fromkeys(
                    (item.get("repository") or {}).get("full_name")
                    for item in items
                    if (item.get("repository") or {}).get("full_name")
                )
            )
            login = logins[0] if logins else target
            return self.ok(
                target,
                Profile(
                    source=self.name,
                    username=login,
                    url=f"https://github.com/{login}" if logins else items[0].get("html_url", ""),
                    display_name=login,
                    bio=f"author of {total} indexed commits",
                    extra={
                        "commits": total,
                        "logins": list(dict.fromkeys(logins)),
                        "repos": repos,
                        "sample_commit": items[0].get("html_url"),
                    },
                ),
            )
        if status in (403, 429):
            return self.blocked(target, f"HTTP {status}: rate limited")
        if status == 422:
            return self.missing(target, "GitHub rejected the email query")
        return self.failed(target, f"HTTP {status}")
