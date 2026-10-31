"""Shared test guards.

The suite is offline by contract (README and AGENTS invariant 1). respx covers
httpx, but a raw socket (the TLS probe, a future tool runner) bypasses it, so
the guard lives at the socket layer. Mark a test ``@pytest.mark.network`` to opt
out.
"""

from __future__ import annotations

import socket

import pytest


class NetworkBlocked(RuntimeError):
    """Raised when a test tries to open a real connection."""


def _deny(*args, **kwargs):
    target = args[0] if args else ""
    raise NetworkBlocked(f"test attempted real network access: {target!r}")


@pytest.fixture(autouse=True)
def block_network(request, monkeypatch):
    if request.node.get_closest_marker("network"):
        return
    monkeypatch.setattr(socket.socket, "connect", _deny)
    monkeypatch.setattr(socket.socket, "connect_ex", _deny)
    monkeypatch.setattr(socket, "create_connection", _deny)
