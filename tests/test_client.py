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
from unittest.mock import MagicMock, patch

import pytest

from terok_clearance.client.client import ClearanceClient
from terok_clearance.hub.server import ClearanceHub

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
    h._verdict_client.apply = _stub_shield_ok  # default: every verdict succeeds
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
    hub._verdict_client.apply = _stub_shield_fail
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


# ── Reconnect loop ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_reconnects_after_hub_restart(private_runtime_dir: Path) -> None:
    """Hub stops + restarts → client's Subscribe loop rebinds automatically."""
    sock_path = private_runtime_dir / "clearance.sock"
    reader_path = private_runtime_dir / "reader.sock"
    hub_1 = ClearanceHub(clearance_socket=sock_path, reader_socket=reader_path)
    hub_1._run_shield = _stub_shield_ok
    await hub_1.start()

    received: list = []

    async def on_event(event) -> None:  # noqa: ANN001
        received.append(event)

    c = ClearanceClient(socket_path=sock_path)
    await c.start(on_event)
    await asyncio.sleep(0.05)

    # Drop the hub, stand a fresh one up on the same path.
    await hub_1.stop()
    await asyncio.sleep(0.05)  # let the client's stream task observe the reset
    hub_2 = ClearanceHub(clearance_socket=sock_path, reader_socket=reader_path)
    hub_2._run_shield = _stub_shield_ok
    await hub_2.start()

    # Skip the client's back-off sleep so the test doesn't drag.
    c.poke_reconnect()
    for _ in range(50):
        await asyncio.sleep(0.05)
        if c._sub_proxy is not None:
            break

    _emit_reader_event(
        reader_path,
        {
            "type": "pending",
            "container": CONTAINER,
            "id": f"{CONTAINER}:2",
            "dest": DEST_IP,
            "port": 443,
            "proto": 6,
            "domain": DOMAIN,
        },
    )
    await asyncio.sleep(0.2)
    try:
        assert any(e.request_id == f"{CONTAINER}:2" for e in received)
    finally:
        with contextlib.suppress(Exception):
            await c.stop()
        with contextlib.suppress(Exception):
            await hub_2.stop()


@pytest.mark.asyncio
async def test_poke_reconnect_is_noop_when_healthy(
    client: tuple[ClearanceClient, list],
) -> None:
    """Poking a connected client must not disturb the live Subscribe() stream."""
    c, _received = client
    c.poke_reconnect()
    await asyncio.sleep(0.05)
    # The internal event was set, but nothing awaits it while the stream
    # loop is inside Subscribe() — verify the client is still serviceable
    # by issuing a verdict.  Any malformed teardown would surface here.
    ok = await c.verdict(CONTAINER, f"{CONTAINER}:unknown", DOMAIN, "allow")
    assert ok is False  # unknown request_id refusal


@pytest.mark.asyncio
async def test_event_callback_exception_is_logged_but_stream_survives(
    hub: ClearanceHub, client: tuple[ClearanceClient, list]
) -> None:
    """A raising callback doesn't kill the stream — next event still arrives."""
    c, received = client
    calls = {"n": 0}

    async def flaky(event) -> None:  # noqa: ANN001
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("first event blows up")
        received.append(event)

    c._on_event = flaky
    _emit_reader_event(
        hub._reader_socket,
        {
            "type": "pending",
            "container": CONTAINER,
            "id": f"{CONTAINER}:1",
            "dest": DEST_IP,
            "port": 443,
            "proto": 6,
            "domain": "a.example",
        },
    )
    await asyncio.sleep(0.1)
    _emit_reader_event(
        hub._reader_socket,
        {
            "type": "pending",
            "container": CONTAINER,
            "id": f"{CONTAINER}:2",
            "dest": DEST_IP,
            "port": 443,
            "proto": 6,
            "domain": "b.example",
        },
    )
    await asyncio.sleep(0.1)
    assert any(e.request_id == f"{CONTAINER}:2" for e in received)


@pytest.mark.asyncio
async def test_start_rollback_on_partial_connect_failure(tmp_path: Path) -> None:
    """If the second transport dial fails, no live socket leaks behind."""
    import terok_clearance.client.client as client_mod

    sock = tmp_path / "clearance.sock"
    first_transport = None
    calls = {"n": 0}

    async def flaky_connect(*args, **kwargs):  # noqa: ANN002,ANN003
        nonlocal first_transport
        calls["n"] += 1
        if calls["n"] == 1:
            # Succeed — the test wants this transport rolled back on failure.
            # MagicMock for the transport because _close_transports calls
            # ``t.close()`` synchronously; AsyncMock would produce an
            # un-awaited coroutine warning.
            first_transport = MagicMock()
            return (first_transport, MagicMock())
        raise OSError("simulated second-connect failure")

    c = ClearanceClient(socket_path=sock)
    with patch.object(client_mod, "connect_unix_varlink", flaky_connect):
        with pytest.raises(OSError, match="simulated second-connect failure"):
            await c.start(lambda _: None)

    assert c._sub_transport is None
    assert c._rpc_transport is None
    assert first_transport is not None
    first_transport.close.assert_called()
