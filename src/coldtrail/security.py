"""Network-target safety helpers.

ColdTrail is an operator tool, but the web UI can be exposed with a shared token.
These helpers keep user-controlled hosts from turning source probes or tools into
SSRF/port-scan primitives. Authorized internal recon can opt in explicitly.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

# Ranges that are not routable on the public internet but are not always covered
# by ``ipaddress.is_private`` (it changed across Python 3.12/3.13). Pinned
# explicitly so the answer does not depend on the interpreter version.
NON_PUBLIC_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",  # CGNAT / carrier-grade NAT
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",  # benchmarking
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
        "2001:db8::/32",
    )
)


def _public_ip(value: str | int) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if any(ip in network for network in NON_PUBLIC_NETWORKS):
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def is_public_host(host: str, *, resolve: bool = True) -> bool:
    """Return True when every resolved address for *host* is public.

    DNS failures return True so the request can fail normally rather than
    turning a resolver outage into a misleading policy block. ``resolve=False``
    still blocks literal private IPs and obvious local names but skips DNS, which
    keeps mocked/offline source tests deterministic.
    """
    value = host.strip().strip("[]")
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        return _public_ip(value)
    if not resolve:
        low = value.casefold().rstrip(".")
        return low not in {"localhost", "localhost.localdomain"} and not low.endswith(".local")
    try:
        infos = socket.getaddrinfo(value, None, type=socket.SOCK_STREAM)
    except OSError:
        return True
    addresses = {info[4][0] for info in infos if info[4]}
    return bool(addresses) and all(_public_ip(address) for address in addresses)


def resolve_public_ips(host: str) -> list[str]:
    """Resolve *host* once and return only public addresses.

    Callers that open a raw socket (the TLS probe) use this to pin the
    connection to the address that was validated, so a second DNS answer cannot
    redirect them into loopback.
    """
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError(f"could not resolve {host}: {exc}") from exc
    addresses = sorted({str(info[4][0]) for info in infos if info[4]})
    if not addresses:
        raise ValueError(f"could not resolve {host}")
    blocked = [address for address in addresses if not _public_ip(address)]
    if blocked:
        raise ValueError(
            f"{host} resolves to non-public address(es): {', '.join(blocked)}; "
            "use --allow-private-targets only for authorized internal recon"
        )
    return addresses


def preferred_public_ip(addresses: list[str]) -> str:
    """Return an IPv4 address when the host publishes one, else the first.

    Dual-stack hosts often return AAAA records before A. A pinned connection
    that always takes ``addresses[0]`` then times out on IPv4-only networks;
    preferring IPv4 keeps the common case working while still pinning to a
    validated address.
    """
    if not addresses:
        raise ValueError("no addresses to pin")
    for address in addresses:
        try:
            if ipaddress.ip_address(address).version == 4:
                return address
        except ValueError:
            continue
    return addresses[0]


def host_of(value: str) -> str | None:
    raw = value.strip()
    if not raw:
        return None
    if "://" in raw:
        parsed = urlsplit(raw)
        if parsed.scheme.casefold() not in ("http", "https"):
            return None
        return parsed.hostname
    parsed = urlsplit(f"//{raw}")
    return parsed.hostname


def ensure_public_target(value: str, *, allow_private: bool = False) -> str:
    """Validate a host/URL before a user-controlled fetch or tool run."""
    host = host_of(value)
    if not host:
        raise ValueError(f"not a valid host or http(s) URL: {value!r}")
    if not allow_private and not is_public_host(host):
        raise ValueError(
            f"private, loopback, or link-local target blocked: {host}; "
            "use --allow-private-targets only for authorized internal recon"
        )
    return host
