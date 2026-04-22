# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""End-to-end ClearanceClient ↔ ClearanceHub tests over a real varlink socket.

Spins a :class:`ClearanceHub` on a throwaway unix socket in a
per-test-temp directory, points a :class:`ClearanceClient` at it, and
exercises the full Subscribe + Verdict round-trips.  The reader→hub
side is driven by a raw unix-socket writer (mimicking terok-shield's
``SocketEmitter``) so the tests don't depend on any real reader
subprocess.

Shield exec is stubbed at the hub level so no actual ``terok-shield``
binary is spawned.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import socket
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from terok_dbus._client import ClearanceClient
from terok_dbus._hub import ClearanceHub

from .conftest import CONTAINER, DEST_IP, DOMAIN

# ── Fixtures ──────────────────────────────────────────────────────────


async def _stub_shield_ok(*args, **kwargs) -> tuple[bool, str]:  # noqa: ANN002,ANN003
    return True, ""


async def _stub_shield_fail(*args, **kwargs) -> tuple[bool, str]:  # noqa: ANN002,ANN003
    return False, "nft lock"


@pytest.fixture
async def hub(private_runtime_dir: Path) -> AsyncIterator[ClearanceHub]:
    """A started :class:`ClearanceHub` with a stubbed shield exec."""
    h = ClearanceHub(
        clearance_socket=private_runtime_dir / "clearance.sock",
        reader_socket=private_runtime_dir / "reader.sock",
    )
    h._run_shield = _stub_shield_ok  # default: every verdict succeeds
    await h.start()
    try:
        yield h
    finally:
        with contextlib.suppress(Exception):
            await h.stop()


@pytest.fixture
async def client(hub: ClearanceHub) -> AsyncIterator[tuple[ClearanceClient, list]]:
    """A connected :class:`ClearanceClient` + a list that collects its events."""
    received: list = []

    async def on_event(event) -> None:  # noqa: ANN001
        received.append(event)

    c = ClearanceClient(socket_path=hub._clearance_socket)
    await c.start(on_event)
    # Give the Subscribe() call a moment to register on the hub.
    await asyncio.sleep(0.05)
    try:
        yield c, received
    finally:
        with contextlib.suppress(Exception):
            await c.stop()


def _emit_reader_event(sock_path: Path, payload: dict) -> None:
    """Write one JSON line to the hub's reader socket — same shape the real reader uses."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(str(sock_path))
    s.sendall((json.dumps(payload) + "\n").encode())
    s.close()


# ── Subscribe round-trips ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_connection_blocked_reaches_subscriber(
    hub: ClearanceHub, client: tuple[ClearanceClient, list]
) -> None:
    """A reader 'pending' event surfaces as a connection_blocked ClearanceEvent."""
    _, received = client
    _emit_reader_event(
        hub._reader_socket,
        {
            "type": "pending",
            "container": CONTAINER,
            "id": f"{CONTAINER}:1",
            "dest": DEST_IP,
            "port": 443,
            "proto": 6,
            "domain": DOMAIN,
        },
    )
    await asyncio.sleep(0.1)
    assert any(e.type == "connection_blocked" for e in received)
    block = next(e for e in received if e.type == "connection_blocked")
    assert block.container == CONTAINER
    assert block.request_id == f"{CONTAINER}:1"
    assert block.domain == DOMAIN


@pytest.mark.asyncio
async def test_multiple_event_types_flow_through(
    hub: ClearanceHub, client: tuple[ClearanceClient, list]
) -> None:
    """Lifecycle + shield-state events land with the right discriminator."""
    _, received = client
    for payload in (
        {"type": "container_started", "container": CONTAINER},
        {"type": "shield_down", "container": CONTAINER},
        {"type": "container_exited", "container": CONTAINER, "reason": "poststop"},
    ):
        _emit_reader_event(hub._reader_socket, payload)
    await asyncio.sleep(0.1)
    types = [e.type for e in received]
    assert "container_started" in types
    assert "shield_down" in types
    assert "container_exited" in types


# ── Verdict round-trips ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_verdict_success_returns_true_and_fans_out(
    hub: ClearanceHub, client: tuple[ClearanceClient, list]
) -> None:
    """Successful Verdict returns True + a verdict_applied event broadcasts."""
    c, received = client
    _emit_reader_event(
        hub._reader_socket,
        {
            "type": "pending",
            "container": CONTAINER,
            "id": f"{CONTAINER}:1",
            "dest": DEST_IP,
            "port": 443,
            "proto": 6,
            "domain": DOMAIN,
        },
    )
    await asyncio.sleep(0.1)

    ok = await c.verdict(CONTAINER, f"{CONTAINER}:1", DOMAIN, "allow")
    await asyncio.sleep(0.1)

    assert ok is True
    verdict_events = [e for e in received if e.type == "verdict_applied"]
    assert len(verdict_events) == 1
    assert verdict_events[0].ok is True
    assert verdict_events[0].action == "allow"


@pytest.mark.asyncio
async def test_verdict_with_unknown_request_id_returns_false(
    hub: ClearanceHub, client: tuple[ClearanceClient, list]
) -> None:
    """Blind verdicts are refused at the hub and collapsed to False client-side."""
    c, _ = client
    ok = await c.verdict(CONTAINER, "never-seen:99", DOMAIN, "allow")
    assert ok is False


@pytest.mark.asyncio
async def test_verdict_with_tuple_mismatch_returns_false(
    hub: ClearanceHub, client: tuple[ClearanceClient, list]
) -> None:
    """Request_id the hub emitted but for a different (container, dest) is refused."""
    c, _ = client
    _emit_reader_event(
        hub._reader_socket,
        {
            "type": "pending",
            "container": CONTAINER,
            "id": f"{CONTAINER}:1",
            "dest": DEST_IP,
            "port": 443,
            "proto": 6,
            "domain": DOMAIN,
        },
    )
    await asyncio.sleep(0.1)

    ok = await c.verdict("wrong-container", f"{CONTAINER}:1", DOMAIN, "allow")
    assert ok is False


@pytest.mark.asyncio
async def test_verdict_with_invalid_action_returns_false(
    hub: ClearanceHub, client: tuple[ClearanceClient, list]
) -> None:
    """``action`` outside {allow, deny} is refused at the hub."""
    c, _ = client
    ok = await c.verdict(CONTAINER, f"{CONTAINER}:1", DOMAIN, "maybe")
    assert ok is False


@pytest.mark.asyncio
async def test_verdict_shield_failure_returns_false_and_fans_out_failure(
    hub: ClearanceHub, client: tuple[ClearanceClient, list]
) -> None:
    """Shield's non-zero exit raises on the caller AND fans out ok=False."""
    hub._run_shield = _stub_shield_fail
    c, received = client
    _emit_reader_event(
        hub._reader_socket,
        {
            "type": "pending",
            "container": CONTAINER,
            "id": f"{CONTAINER}:1",
            "dest": DEST_IP,
            "port": 443,
            "proto": 6,
            "domain": DOMAIN,
        },
    )
    await asyncio.sleep(0.1)

    ok = await c.verdict(CONTAINER, f"{CONTAINER}:1", DOMAIN, "allow")
    await asyncio.sleep(0.1)

    assert ok is False
    verdict_events = [e for e in received if e.type == "verdict_applied"]
    assert len(verdict_events) == 1
    assert verdict_events[0].ok is False


# ── Client lifecycle ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_verdict_before_start_returns_false() -> None:
    """Calling ``verdict()`` without ``start()`` is a logged no-op."""
    c = ClearanceClient(socket_path=Path("/dev/null"))
    ok = await c.verdict(CONTAINER, f"{CONTAINER}:1", DOMAIN, "allow")
    assert ok is False
