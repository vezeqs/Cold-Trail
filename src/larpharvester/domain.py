from __future__ import annotations

import asyncio
from typing import Any

from .http import Fetcher, FetchError
from .utils import dedupe

RDAP = "https://rdap.org/domain"
DOH = "https://dns.google/resolve"
CRTSH = "https://crt.sh/"

RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "CNAME")


async def rdap(fetcher: Fetcher, domain: str) -> dict[str, Any] | None:
    try:
        status, data = await fetcher.get_json(f"{RDAP}/{domain}")
    except FetchError:
        return None
    if status != 200 or not isinstance(data, dict):
        return None
    return {
        "handle": data.get("handle"),
        "ldh_name": data.get("ldhName"),
        "status": data.get("status"),
        "events": {
            event.get("eventAction"): event.get("eventDate")
            for event in data.get("events") or []
            if event.get("eventAction")
        },
        "nameservers": [
            server.get("ldhName")
            for server in data.get("nameservers") or []
            if server.get("ldhName")
        ],
        "entities": [
            {
                "roles": entity.get("roles"),
                "handle": entity.get("handle"),
            }
            for entity in data.get("entities") or []
        ],
    }


async def dns(fetcher: Fetcher, name: str, record_type: str) -> list[str]:
    try:
        status, data = await fetcher.get_json(DOH, params={"name": name, "type": record_type})
    except FetchError:
        return []
    if status != 200 or not isinstance(data, dict):
        return []
    answers = data.get("Answer") or []
    return dedupe([str(answer.get("data")) for answer in answers if answer.get("data")])


async def crtsh(fetcher: Fetcher, domain: str, limit: int = 200) -> list[str]:
    try:
        status, data = await fetcher.get_json(CRTSH, params={"q": f"%.{domain}", "output": "json"})
    except FetchError:
        return []
    if status != 200 or not isinstance(data, list):
        return []
    names: list[str] = []
    for entry in data[:limit]:
        for value in str(entry.get("name_value") or "").splitlines():
            value = value.strip().lstrip("*.").casefold()
            if value and value.endswith(domain):
                names.append(value)
    return dedupe(sorted(names))


async def lookup_domain(fetcher: Fetcher, domain: str) -> dict[str, Any]:
    domain = domain.strip().casefold().removeprefix("http://").removeprefix("https://")
    domain = domain.split("/")[0]
    values = await asyncio.gather(
        *(dns(fetcher, domain, record_type) for record_type in RECORD_TYPES)
    )
    records = dict(zip(RECORD_TYPES, values, strict=True))
    return {
        "domain": domain,
        "rdap": await rdap(fetcher, domain),
        "dns": {key: value for key, value in records.items() if value},
        "subdomains": await crtsh(fetcher, domain),
    }


def arpa_name(address: str) -> str | None:
    parts = address.split(".")
    if len(parts) != 4 or not all(part.isdigit() for part in parts):
        return None
    return ".".join(reversed(parts)) + ".in-addr.arpa"


async def ptr(fetcher: Fetcher, address: str) -> list[str]:
    name = arpa_name(address)
    if not name:
        return []
    return await dns(fetcher, name, "PTR")


async def reverse_ip(fetcher: Fetcher, address: str, key: str | None = None) -> list[str]:
    if key:
        try:
            status, data = await fetcher.get_json(
                "https://api.shodan.io/dns/reverse", params={"ips": address, "key": key}
            )
        except FetchError:
            return []
        if status == 200 and isinstance(data, dict):
            return dedupe([str(value) for value in data.get(address, [])])
        return []
    try:
        status, text = await fetcher.get_text(
            "https://api.hackertarget.com/reverseiplookup/", params={"q": address}
        )
    except FetchError:
        return []
    if status != 200:
        return []
    low = text.casefold()[:200]
    if "error" in low or "exceeded" in low or "quota" in low:
        return []
    return dedupe([line.strip() for line in text.splitlines() if line.strip()])[:200]


async def shodan_host(
    fetcher: Fetcher, address: str, key: str | None = None
) -> dict[str, Any] | None:
    if not key:
        return None
    try:
        status, data = await fetcher.get_json(
            f"https://api.shodan.io/shodan/host/{address}", params={"key": key}
        )
    except FetchError:
        return None
    if status != 200 or not isinstance(data, dict):
        return None
    return {
        "ports": data.get("ports"),
        "hostnames": data.get("hostnames"),
        "org": data.get("org"),
        "isp": data.get("isp"),
        "os": data.get("os"),
        "country": data.get("country_name"),
        "city": data.get("city"),
        "vulns": list((data.get("vulns") or {}).keys()),
        "last_update": data.get("last_update"),
    }
