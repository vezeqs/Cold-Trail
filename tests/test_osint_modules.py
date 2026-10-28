from __future__ import annotations

import httpx
import pytest
import respx

from coldtrail.config import Settings
from coldtrail.domain import (
    arpa_name,
    crtsh,
    dns,
    lookup_domain,
    ptr,
    rdap,
    reverse_ip,
    shodan_host,
)
from coldtrail.http import Fetcher
from coldtrail.phone import lookup as phone_lookup
from coldtrail.wayback import cdx, snapshot


def test_phone_lookup():
    payload = phone_lookup("+351 912 345 678")
    assert payload is not None
    assert payload["e164"] == "+351912345678"
    assert payload["country_code"] == 351
    assert "Europe/Lisbon" in payload["timezones"]


def test_phone_invalid():
    assert phone_lookup("123") is None
    assert phone_lookup("not a number") is None


@pytest.fixture
def settings(tmp_path):
    return Settings(db_path=tmp_path / "t.db", requests_per_second=0, jitter=0)


@respx.mock
async def test_rdap(settings):
    respx.get("https://rdap.org/domain/example.com").mock(
        return_value=httpx.Response(
            200,
            json={
                "ldhName": "EXAMPLE.COM",
                "status": ["active"],
                "events": [{"eventAction": "registration", "eventDate": "1995-08-14"}],
                "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}],
                "entities": [{"roles": ["registrar"], "handle": "376"}],
            },
        )
    )
    async with Fetcher(settings) as fetcher:
        payload = await rdap(fetcher, "example.com")
    assert payload["nameservers"] == ["A.IANA-SERVERS.NET"]
    assert payload["events"]["registration"] == "1995-08-14"


@respx.mock
async def test_dns(settings):
    respx.get("https://dns.google/resolve").mock(
        return_value=httpx.Response(
            200, json={"Answer": [{"data": "93.184.216.34"}, {"data": "93.184.216.34"}]}
        )
    )
    async with Fetcher(settings) as fetcher:
        assert await dns(fetcher, "example.com", "A") == ["93.184.216.34"]


@respx.mock
async def test_crtsh(settings):
    respx.get("https://crt.sh/").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"name_value": "www.example.com"},
                {"name_value": "*.example.com\napi.example.com"},
            ],
        )
    )
    async with Fetcher(settings) as fetcher:
        names = await crtsh(fetcher, "example.com")
    assert names == ["api.example.com", "example.com", "www.example.com"]


@respx.mock
async def test_lookup_domain(settings):
    respx.get("https://rdap.org/domain/example.com").mock(
        return_value=httpx.Response(200, json={"ldhName": "EXAMPLE.COM"})
    )
    respx.get("https://dns.google/resolve").mock(
        return_value=httpx.Response(200, json={"Answer": [{"data": "1.2.3.4"}]})
    )
    respx.get("https://crt.sh/").mock(return_value=httpx.Response(200, json=[]))
    async with Fetcher(settings) as fetcher:
        payload = await lookup_domain(fetcher, "https://example.com/path")
    assert payload["domain"] == "example.com"
    assert payload["dns"]["A"] == ["1.2.3.4"]


@respx.mock
async def test_wayback_cdx(settings):
    respx.get("https://web.archive.org/cdx/search/cdx").mock(
        return_value=httpx.Response(
            200,
            json=[
                ["timestamp", "original", "statuscode", "mimetype", "digest", "length"],
                ["20200101000000", "https://example.com/", "200", "text/html", "abc", "123"],
            ],
        )
    )
    async with Fetcher(settings) as fetcher:
        rows = await cdx(fetcher, "https://example.com/")
    assert rows[0]["timestamp"] == "20200101000000"
    assert rows[0]["statuscode"] == "200"


@respx.mock
async def test_wayback_snapshot(settings):
    respx.get("https://web.archive.org/web/20200101000000id_/https://example.com/").mock(
        return_value=httpx.Response(200, text="<html>old</html>")
    )
    async with Fetcher(settings) as fetcher:
        text = await snapshot(fetcher, "20200101000000", "https://example.com/")
    assert text == "<html>old</html>"


def test_arpa_name():
    assert arpa_name("8.8.8.8") == "8.8.8.8.in-addr.arpa"
    assert arpa_name("not-an-ip") is None


@respx.mock
async def test_ptr(settings):
    respx.get("https://dns.google/resolve").mock(
        return_value=httpx.Response(200, json={"Answer": [{"data": "dns.google."}]})
    )
    async with Fetcher(settings) as fetcher:
        assert await ptr(fetcher, "8.8.8.8") == ["dns.google."]


@respx.mock
async def test_reverse_ip_without_key(settings):
    respx.get("https://api.hackertarget.com/reverseiplookup/").mock(
        return_value=httpx.Response(200, text="a.example.com\nb.example.com\n")
    )
    async with Fetcher(settings) as fetcher:
        assert await reverse_ip(fetcher, "1.2.3.4") == ["a.example.com", "b.example.com"]


@respx.mock
async def test_reverse_ip_with_shodan(settings):
    respx.get("https://api.shodan.io/dns/reverse").mock(
        return_value=httpx.Response(200, json={"1.2.3.4": ["a.example.com"]})
    )
    async with Fetcher(settings) as fetcher:
        assert await reverse_ip(fetcher, "1.2.3.4", "key") == ["a.example.com"]


@respx.mock
async def test_shodan_host(settings):
    respx.get("https://api.shodan.io/shodan/host/1.2.3.4").mock(
        return_value=httpx.Response(
            200,
            json={
                "ports": [80, 443],
                "hostnames": ["a.example.com"],
                "org": "Example",
                "vulns": {"CVE-2020-0001": {}},
            },
        )
    )
    async with Fetcher(settings) as fetcher:
        payload = await shodan_host(fetcher, "1.2.3.4", "key")
    assert payload["ports"] == [80, 443]
    assert payload["vulns"] == ["CVE-2020-0001"]


async def test_shodan_host_without_key(settings):
    async with Fetcher(settings) as fetcher:
        assert await shodan_host(fetcher, "1.2.3.4") is None
