from __future__ import annotations

import asyncio
import base64
import contextlib
import ssl
import struct
from typing import Any

from .http import Fetcher, FetchError
from .utils import dedupe

RDAP = "https://rdap.org/domain"
RDAP_IP = "https://rdap.org/ip"
RIPE_ASN = "https://stat.ripe.net/data/network-info/data.json"
RIPE_PREFIXES = "https://stat.ripe.net/data/announced-prefixes/data.json"
RIPE_OVERVIEW = "https://stat.ripe.net/data/as-overview/data.json"
DOH = "https://dns.google/resolve"
CRTSH = "https://crt.sh/"

RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "CNAME")

MX_PROVIDERS = {
    "google.com": "Google Workspace",
    "googlemail.com": "Google Workspace",
    "outlook.com": "Microsoft 365",
    "protection.outlook.com": "Microsoft 365",
    "protonmail.ch": "Proton Mail",
    "pphosted.com": "Proofpoint",
    "mimecast.com": "Mimecast",
    "zoho.com": "Zoho Mail",
    "fastmail.com": "Fastmail",
    "yahoodns.net": "Yahoo Mail",
    "icloud.com": "Apple iCloud",
    "cloudflare.net": "Cloudflare Email Routing",
    "amazonaws.com": "Amazon SES",
    "mailgun.org": "Mailgun",
    "sendgrid.net": "SendGrid",
}

TAKEOVER_CNAMES: dict[str, tuple[str, str]] = {
    "github.io": ("GitHub Pages", "There isn't a GitHub Pages site here"),
    "herokuapp.com": ("Heroku", "No such app"),
    "vercel.app": ("Vercel", "The deployment could not be found"),
    "netlify.app": ("Netlify", "Not Found - Request ID"),
    "azurewebsites.net": ("Azure App Service", "404 Web Site not found"),
    "s3.amazonaws.com": ("AWS S3", "NoSuchBucket"),
    "ghost.io": ("Ghost", "The thing you were looking for is no longer here"),
    "myshopify.com": ("Shopify", "Sorry, this shop is currently unavailable"),
}


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


def guess_mx_provider(mx_records: list[str]) -> str | None:
    for record in mx_records:
        low = record.casefold().rstrip(".")
        for suffix, provider in MX_PROVIDERS.items():
            if low.endswith(suffix):
                return provider
    return None


def extract_spf(txt_records: list[str]) -> str | None:
    for record in txt_records:
        cleaned = record.strip().strip('"')
        if cleaned.casefold().startswith("v=spf1"):
            return cleaned
    return None


async def fetch_dmarc(fetcher: Fetcher, domain: str) -> str | None:
    records = await dns(fetcher, f"_dmarc.{domain}", "TXT")
    for record in records:
        cleaned = record.strip().strip('"')
        if "v=dmarc1" in cleaned.casefold():
            return cleaned
    return None


async def fetch_security_txt(fetcher: Fetcher, domain: str) -> str | None:
    for path in (f"https://{domain}/.well-known/security.txt", f"https://{domain}/security.txt"):
        try:
            status, text = await fetcher.get_text(path)
        except FetchError:
            continue
        if status == 200 and "contact:" in text.casefold():
            return text.strip()[:2000]
    return None


def mmh3_32(data: bytes, seed: int = 0) -> int:
    """Pure-Python 32-bit signed MurmurHash3 (matches Shodan's http.favicon.hash)."""
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    rounded_end = length & ~0x3

    for i in range(0, rounded_end, 4):
        k1 = struct.unpack_from("<I", data, i)[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    k1 = 0
    tail = length & 3
    if tail == 3:
        k1 ^= data[rounded_end + 2] << 16
    if tail >= 2:
        k1 ^= data[rounded_end + 1] << 8
    if tail >= 1:
        k1 ^= data[rounded_end]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def favicon_shodan_hash(raw: bytes) -> int:
    """Compute Shodan's base64-with-newlines MurmurHash3 for a favicon."""
    b64 = base64.encodebytes(raw)
    return mmh3_32(b64)


async def fetch_favicon_hash(fetcher: Fetcher, domain: str) -> int | None:
    try:
        response = await fetcher.get(f"https://{domain}/favicon.ico")
    except FetchError:
        return None
    if response.status != 200 or not response.content:
        return None
    return favicon_shodan_hash(response.content)


async def check_subdomain_takeover(
    fetcher: Fetcher, domain: str, cname_records: list[str]
) -> dict[str, str] | None:
    for cname in cname_records:
        low = cname.casefold().rstrip(".")
        for suffix, (service, fingerprint) in TAKEOVER_CNAMES.items():
            if low.endswith(suffix):
                try:
                    status, text = await fetcher.get_text(f"http://{domain}")
                except FetchError:
                    continue
                if fingerprint.casefold() in text.casefold():
                    return {"service": service, "cname": cname, "status": str(status)}
    return None


async def lookup_domain(fetcher: Fetcher, domain: str, *, deep: bool = False) -> dict[str, Any]:
    domain = domain.strip().casefold().removeprefix("http://").removeprefix("https://")
    domain = domain.split("/")[0]
    values = await asyncio.gather(
        *(dns(fetcher, domain, record_type) for record_type in RECORD_TYPES)
    )
    records = dict(zip(RECORD_TYPES, values, strict=True))
    dns_map = {key: value for key, value in records.items() if value}
    result: dict[str, Any] = {
        "domain": domain,
        "rdap": await rdap(fetcher, domain),
        "dns": dns_map,
        "subdomains": await crtsh(fetcher, domain),
    }
    mx = dns_map.get("MX") or []
    txt = dns_map.get("TXT") or []
    cname = dns_map.get("CNAME") or []
    provider = guess_mx_provider(mx)
    spf = extract_spf(txt)
    if provider:
        result["mx_provider"] = provider
    if spf:
        result["spf"] = spf
    if deep:
        dmarc, sec_txt, fav_hash, takeover, tls = await asyncio.gather(
            fetch_dmarc(fetcher, domain),
            fetch_security_txt(fetcher, domain),
            fetch_favicon_hash(fetcher, domain),
            check_subdomain_takeover(fetcher, domain, cname),
            tls_cert_info(domain),
        )
        result["dmarc"] = dmarc
        result["security_txt"] = sec_txt
        result["favicon_mmh3"] = fav_hash
        result["takeover"] = takeover
        result["tls"] = tls
    return result


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


async def asn_lookup(fetcher: Fetcher, address: str) -> dict[str, Any] | None:
    """Query RIPE Stat for ASN and prefix announcement of an IP."""
    try:
        status, data = await fetcher.get_json(RIPE_ASN, params={"resource": address})
    except FetchError:
        return None
    if status != 200 or not isinstance(data, dict):
        return None
    inner = data.get("data") or {}
    asns = inner.get("asns") or []
    prefix = inner.get("prefix")
    if not asns and not prefix:
        return None
    return {"asns": [str(a) for a in asns], "prefix": prefix}


async def bgp_prefixes(fetcher: Fetcher, resource: str) -> dict[str, Any] | None:
    """RIPE Stat ASN overview + announced prefixes (accepts ASN or IP)."""
    value = resource.strip().upper()
    if value.startswith("AS"):
        asn = value
    elif "." in value or ":" in value:
        info = await asn_lookup(fetcher, value)
        if not info or not info.get("asns"):
            return None
        asn = f"AS{info['asns'][0]}"
    else:
        asn = f"AS{value}"
    try:
        status, data = await fetcher.get_json(RIPE_PREFIXES, params={"resource": asn})
        status2, overview = await fetcher.get_json(RIPE_OVERVIEW, params={"resource": asn})
    except FetchError:
        return None
    prefixes: list[str] = []
    if status == 200 and isinstance(data, dict):
        for item in (data.get("data") or {}).get("prefixes") or []:
            if isinstance(item, dict) and item.get("prefix"):
                prefixes.append(str(item["prefix"]))
    holder = None
    if status2 == 200 and isinstance(overview, dict):
        holder = (overview.get("data") or {}).get("holder")
    if not prefixes and not holder:
        return None
    return {"asn": asn, "holder": holder, "announced": dedupe(prefixes)}


async def crtsh_identities(fetcher: Fetcher, query: str, limit: int = 100) -> list[dict[str, Any]]:
    """Search certificate transparency for certificates matching an identity query."""
    try:
        status, data = await fetcher.get_json(CRTSH, params={"q": query, "output": "json"})
    except FetchError:
        return []
    if status != 200 or not isinstance(data, list):
        return []
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in data:
        if not isinstance(entry, dict):
            continue
        common = entry.get("common_name") or entry.get("name_value")
        issuer = entry.get("issuer_name") or ""
        if not common:
            continue
        key = (str(common), str(issuer))
        if key in out:
            continue
        out[key] = {
            "common_name": str(common),
            "issuer": str(issuer),
            "not_before": entry.get("not_before"),
            "not_after": entry.get("not_after"),
        }
        if len(out) >= limit:
            break
    return list(out.values())


async def tls_cert_info(
    domain: str, port: int = 443, timeout: float = 6.0
) -> dict[str, Any] | None:
    """Perform a live TLS handshake and extract subject, issuer, SANs, and validity."""
    context = ssl.create_default_context()
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(domain, port, ssl=context, server_hostname=domain),
            timeout=timeout,
        )
    except (TimeoutError, OSError, ssl.SSLError):
        return None
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        if ssl_object is None:
            return None
        cert = ssl_object.getpeercert() or {}
        subject = {key: value for item in cert.get("subject", ()) for key, value in item}
        issuer = {key: value for item in cert.get("issuer", ()) for key, value in item}
        sans = [value for key, value in cert.get("subjectAltName", ()) if key == "DNS"]
        return {
            "subject_cn": subject.get("commonName"),
            "subject_org": subject.get("organizationName"),
            "issuer_cn": issuer.get("commonName"),
            "issuer_org": issuer.get("organizationName"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "serial": cert.get("serialNumber"),
            "sans": sans,
            "tls_version": ssl_object.version(),
        }
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def rdap_ip(fetcher: Fetcher, address: str) -> dict[str, Any] | None:
    try:
        status, data = await fetcher.get_json(f"{RDAP_IP}/{address}")
    except FetchError:
        return None
    if status != 200 or not isinstance(data, dict):
        return None
    return {
        "name": data.get("name"),
        "handle": data.get("handle"),
        "country": data.get("country"),
        "start_address": data.get("startAddress"),
        "end_address": data.get("endAddress"),
    }


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
