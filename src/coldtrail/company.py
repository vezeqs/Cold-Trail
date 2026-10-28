"""Corporate and sanctions lookup providers."""

from __future__ import annotations

import base64
from typing import Any

from .config import Settings
from .http import Fetcher
from .utils import sensitive_cache_key


def _item(provider: str, name: Any, **extra: Any) -> dict[str, Any]:
    return {"provider": provider, "name": str(name or ""), **extra}


async def opensanctions(fetcher: Fetcher, query: str, limit: int, key: str) -> list[dict[str, Any]]:
    status, data = await fetcher.get_json(
        "https://api.opensanctions.org/search/default",
        params={"q": query, "limit": limit},
        headers={"Authorization": f"ApiKey {key}"},
    )
    if status != 200 or not isinstance(data, dict):
        return []
    return [
        _item(
            "opensanctions",
            item.get("caption"),
            id=item.get("id"),
            schema=item.get("schema"),
            datasets=item.get("datasets"),
            score=item.get("score"),
        )
        for item in data.get("results") or []
        if isinstance(item, dict)
    ][:limit]


async def opencorporates(
    fetcher: Fetcher, query: str, limit: int, key: str
) -> list[dict[str, Any]]:
    status, data = await fetcher.get_json(
        "https://api.opencorporates.com/v0.4/companies/search",
        params={"q": query, "per_page": limit, "api_token": key},
        cache_key=sensitive_cache_key("opencorporates", query),
    )
    if status != 200 or not isinstance(data, dict):
        return []
    companies = (data.get("results") or {}).get("companies") or []
    return [
        _item(
            "opencorporates",
            (item.get("company") or {}).get("name"),
            jurisdiction=(item.get("company") or {}).get("jurisdiction_code"),
            number=(item.get("company") or {}).get("company_number"),
            status=(item.get("company") or {}).get("current_status"),
        )
        for item in companies
        if isinstance(item, dict)
    ][:limit]


async def companies_house(
    fetcher: Fetcher, query: str, limit: int, key: str
) -> list[dict[str, Any]]:
    token = base64.b64encode(f"{key}:".encode()).decode()
    status, data = await fetcher.get_json(
        "https://api.company-information.service.gov.uk/search/companies",
        params={"q": query, "items_per_page": limit},
        headers={"Authorization": f"Basic {token}"},
        cache_key=sensitive_cache_key("companies-house", query),
    )
    if status != 200 or not isinstance(data, dict):
        return []
    return [
        _item(
            "companies-house",
            item.get("title"),
            number=item.get("company_number"),
            status=item.get("company_status"),
            address=item.get("address_snippet"),
        )
        for item in data.get("items") or []
        if isinstance(item, dict)
    ][:limit]


async def company_search(
    fetcher: Fetcher,
    query: str,
    settings: Settings,
    *,
    provider: str = "auto",
    limit: int = 10,
) -> list[dict[str, Any]]:
    provider = provider.casefold()
    if provider == "auto":
        if settings.opensanctions_api_key:
            provider = "opensanctions"
        elif settings.opencorporates_api_key:
            provider = "opencorporates"
        elif settings.companies_house_api_key:
            provider = "companies-house"
        else:
            raise ValueError(
                "no company provider configured; set OPENSANCTIONS_API_KEY, "
                "OPENCORPORATES_API_KEY, or COMPANIES_HOUSE_API_KEY"
            )
    if provider == "opensanctions":
        if not settings.opensanctions_api_key:
            raise ValueError("OPENSANCTIONS_API_KEY is not configured")
        return await opensanctions(fetcher, query, limit, settings.opensanctions_api_key)
    if provider == "opencorporates":
        if not settings.opencorporates_api_key:
            raise ValueError("OPENCORPORATES_API_KEY is not configured")
        return await opencorporates(fetcher, query, limit, settings.opencorporates_api_key)
    if provider in {"companies-house", "companies_house"}:
        if not settings.companies_house_api_key:
            raise ValueError("COMPANIES_HOUSE_API_KEY is not configured")
        return await companies_house(fetcher, query, limit, settings.companies_house_api_key)
    if provider == "all":
        results: list[dict[str, Any]] = []
        if settings.opensanctions_api_key:
            results += await opensanctions(fetcher, query, limit, settings.opensanctions_api_key)
        if settings.opencorporates_api_key:
            results += await opencorporates(fetcher, query, limit, settings.opencorporates_api_key)
        if settings.companies_house_api_key:
            results += await companies_house(
                fetcher, query, limit, settings.companies_house_api_key
            )
        return results
    raise ValueError(f"unknown company provider: {provider}")
