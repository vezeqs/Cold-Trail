"""Network-target safety helpers.

ColdTrail is an operator tool, but the web UI can be exposed with a shared token.
These helpers keep user-controlled hosts from turning source probes or tools into
SSRF/port-scan primitives. Authorized internal recon can opt in explicitly.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit


def _public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
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
