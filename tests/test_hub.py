# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for :class:`ClearanceHub` — state machine in isolation.

Exercises the hub's internals (authz binding map, fan-out queues,
reader translation, verdict dispatch) without going through the varlink
transport.  End-to-end varlink round-trips live in ``test_client.py``.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from terok_dbus._hub import ClearanceHub, _translate_reader_event
from terok_dbus._wire import (
    ClearanceEvent,
    InvalidAction,
    ShieldCliFailed,
    UnknownRequest,
    VerdictTupleMismatch,
)

from .conftest import CONTAINER, DEST_IP, DOMAIN

# ── Reader-event translation ──────────────────────────────────────────


class TestTranslateReaderEvent:
    """Ingester-dict → ClearanceEvent shape tests."""

    def test_connection_blocked_populates_all_fields(self) -> None:
        event = _translate_reader_event(
            "connection_blocked",
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
        assert event.type == "connection_blocked"
        assert event.container == CONTAINER
        assert event.request_id == f"{CONTAINER}:1"
        assert event.dest == DEST_IP
        assert event.port == 443
        assert event.proto == 6
        assert event.domain == DOMAIN

    def test_connection_blocked_defaults_missing_domain(self) -> None:
        """Reader sometimes hasn't resolved a domain yet; fall through to empty."""
        event = _translate_reader_event(
            "connection_blocked",
            {
                "type": "pending",
                "container": CONTAINER,
                "id": f"{CONTAINER}:1",
                "dest": DEST_IP,
                "port": 443,
                "proto": 6,
            },
        )
        assert event.domain == ""

    def test_container_exited_carries_reason(self) -> None:
        event = _translate_reader_event(
            "container_exited",
            {"type": "container_exited", "container": CONTAINER, "reason": "poststop"},
        )
        assert event.reason == "poststop"

    def test_shield_state_event_has_only_container(self) -> None:
        event = _translate_reader_event(
            "shield_down", {"type": "shield_down", "container": CONTAINER}
        )
        assert event.type == "shield_down"
        assert event.container == CONTAINER
        assert event.request_id == ""


# ── Live-verdict authz binding ────────────────────────────────────────


def _hub() -> ClearanceHub:
    """Build an unstarted hub — state maps are fine to test without sockets."""
    return ClearanceHub()


def _blocked(request_id: str = f"{CONTAINER}:1", *, domain: str = DOMAIN) -> ClearanceEvent:
    return ClearanceEvent(
        type="connection_blocked",
        container=CONTAINER,
        request_id=request_id,
        dest=DEST_IP,
        port=443,
        proto=6,
        domain=domain,
    )


class TestUpdateLiveVerdicts:
    """Authz-binding map grows and shrinks in lockstep with events."""

    def test_connection_blocked_records_domain_as_target(self) -> None:
        """Domain beats raw IP — shield dispatches ``allow_domain`` on shape."""
        hub = _hub()
        hub._update_live_verdicts(_blocked())
        assert f"{CONTAINER}:1" in hub._live_verdicts
        live = hub._live_verdicts[f"{CONTAINER}:1"]
        assert live.container == CONTAINER
        assert live.dest == DOMAIN

    def test_connection_blocked_falls_back_to_dest_when_no_domain(self) -> None:
        """Readers without dnsmasq resolution pass an empty domain."""
        hub = _hub()
        hub._update_live_verdicts(_blocked(domain=""))
        assert hub._live_verdicts[f"{CONTAINER}:1"].dest == DEST_IP

    def test_shield_down_purges_bindings_for_container(self) -> None:
        """Bypass means pending blocks are stale; drop them."""
        hub = _hub()
        hub._update_live_verdicts(_blocked(f"{CONTAINER}:1"))
        hub._update_live_verdicts(_blocked(f"{CONTAINER}:2"))
        hub._update_live_verdicts(ClearanceEvent(type="shield_down", container=CONTAINER))
        assert hub._live_verdicts == {}

    def test_container_exited_purges_bindings(self) -> None:
        hub = _hub()
        hub._update_live_verdicts(_blocked())
        hub._update_live_verdicts(ClearanceEvent(type="container_exited", container=CONTAINER))
        assert hub._live_verdicts == {}

    def test_unrelated_container_not_purged(self) -> None:
        """ShieldDown for container A mustn't drop bindings for container B."""
        hub = _hub()
        hub._update_live_verdicts(_blocked(f"{CONTAINER}:1"))
        hub._update_live_verdicts(
            ClearanceEvent(
                type="connection_blocked",
                container="other",
                request_id="other:9",
                dest=DEST_IP,
                port=80,
                proto=6,
                domain="",
            )
        )
        hub._update_live_verdicts(ClearanceEvent(type="shield_down", container="other"))
        assert f"{CONTAINER}:1" in hub._live_verdicts
        assert "other:9" not in hub._live_verdicts


# ── Fan-out ───────────────────────────────────────────────────────────


class TestFanOut:
    """``_fan_out`` copies one event into every subscriber queue."""

    def test_single_subscriber_receives_event(self) -> None:
        hub = _hub()
        q: asyncio.Queue = asyncio.Queue(maxsize=4)
        hub._subscribers.add(q)
        event = _blocked()
        hub._fan_out(event)
        assert q.get_nowait() is event

    def test_full_queue_drops_oldest(self) -> None:
        """Slow subscribers lose the oldest event rather than blocking fan-out."""
        hub = _hub()
        q: asyncio.Queue = asyncio.Queue(maxsize=2)
        hub._subscribers.add(q)
        for i in range(4):
            hub._fan_out(_blocked(f"{CONTAINER}:{i}"))
        assert q.qsize() == 2
        latest = q.get_nowait()
        second = q.get_nowait()
        assert latest.request_id == f"{CONTAINER}:2"
        assert second.request_id == f"{CONTAINER}:3"

    def test_fan_out_touches_every_subscriber(self) -> None:
        hub = _hub()
        queues = [asyncio.Queue(maxsize=4) for _ in range(3)]
        for q in queues:
            hub._subscribers.add(q)
        hub._fan_out(_blocked())
        for q in queues:
            assert q.qsize() == 1


# ── Verdict dispatch ──────────────────────────────────────────────────


async def _stub_shield_ok(*args, **kwargs) -> tuple[bool, str]:  # noqa: ANN002,ANN003
    return True, ""


async def _stub_shield_fail(*args, **kwargs) -> tuple[bool, str]:  # noqa: ANN002,ANN003
    return False, "nft lock"


class TestApplyVerdict:
    """``_apply_verdict`` enforces the four refusal paths + fans out success."""

    @pytest.mark.asyncio
    async def test_refuses_unknown_action(self) -> None:
        hub = _hub()
        with pytest.raises(InvalidAction) as exc_info:
            await hub._apply_verdict(CONTAINER, f"{CONTAINER}:1", DOMAIN, "maybe")
        assert exc_info.value.action == "maybe"

    @pytest.mark.asyncio
    async def test_refuses_unknown_request_id(self) -> None:
        hub = _hub()
        with pytest.raises(UnknownRequest) as exc_info:
            await hub._apply_verdict(CONTAINER, "ghost:42", DOMAIN, "allow")
        assert exc_info.value.request_id == "ghost:42"

    @pytest.mark.asyncio
    async def test_refuses_tuple_mismatch(self) -> None:
        """A request_id the hub emitted but for a different (container, dest)."""
        hub = _hub()
        hub._update_live_verdicts(_blocked())
        with pytest.raises(VerdictTupleMismatch) as exc_info:
            await hub._apply_verdict("wrong-container", f"{CONTAINER}:1", DOMAIN, "allow")
        assert exc_info.value.expected_container == CONTAINER
        assert exc_info.value.got_container == "wrong-container"
        # Entry survives so a subsequent matching verdict still works.
        assert f"{CONTAINER}:1" in hub._live_verdicts

    @pytest.mark.asyncio
    async def test_success_fans_out_verdict_applied_event(self) -> None:
        hub = _hub()
        hub._update_live_verdicts(_blocked())
        hub._run_shield = _stub_shield_ok
        q: asyncio.Queue = asyncio.Queue(maxsize=4)
        hub._subscribers.add(q)

        ok = await hub._apply_verdict(CONTAINER, f"{CONTAINER}:1", DOMAIN, "allow")

        assert ok is True
        # Live binding released on success.
        assert hub._live_verdicts == {}
        # Every subscriber sees a verdict_applied event.
        event = q.get_nowait()
        assert event.type == "verdict_applied"
        assert event.ok is True
        assert event.action == "allow"

    @pytest.mark.asyncio
    async def test_shield_failure_raises_and_still_fans_out(self) -> None:
        """Shield failure flows BOTH as a raised error AND as ok=false event."""
        hub = _hub()
        hub._update_live_verdicts(_blocked())
        hub._run_shield = _stub_shield_fail
        q: asyncio.Queue = asyncio.Queue(maxsize=4)
        hub._subscribers.add(q)

        with pytest.raises(ShieldCliFailed) as exc_info:
            await hub._apply_verdict(CONTAINER, f"{CONTAINER}:1", DOMAIN, "allow")

        assert exc_info.value.stderr == "nft lock"
        event = q.get_nowait()
        assert event.type == "verdict_applied"
        assert event.ok is False


# ── Shield subprocess dispatch ────────────────────────────────────────


class TestRunShield:
    """``_run_shield`` translates subprocess outcomes into (ok, stderr) tuples."""

    @pytest.mark.asyncio
    async def test_missing_shield_binary(self) -> None:
        hub = ClearanceHub(shield_binary=None)
        hub._shield_binary = None
        ok, msg = await hub._run_shield(CONTAINER, DOMAIN, "allow")
        assert ok is False
        assert "terok-shield" in msg

    @pytest.mark.asyncio
    async def test_success_returns_ok(self) -> None:
        hub = ClearanceHub(shield_binary="/bin/true")
        proc = AsyncMock()
        proc.communicate = AsyncMock(return_value=(b"", b""))
        proc.returncode = 0
        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
            ok, msg = await hub._run_shield(CONTAINER, DOMAIN, "allow")
        assert ok is True
        assert msg == ""

    @pytest.mark.asyncio
    async def test_nonzero_exit_returns_stderr_snippet(self) -> None:
        hub = ClearanceHub(shield_binary="/bin/true")
        proc = AsyncMock()
        proc.communicate = AsyncMock(return_value=(b"", b"boom\n"))
        proc.returncode = 1
        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
            ok, msg = await hub._run_shield(CONTAINER, DOMAIN, "allow")
        assert ok is False
        assert msg == "boom"

    @pytest.mark.asyncio
    async def test_timeout_kills_process(self) -> None:
        hub = ClearanceHub(shield_binary="/bin/true")
        proc = AsyncMock()
        proc.communicate = AsyncMock(side_effect=TimeoutError)
        proc.kill = lambda: None
        with (
            patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)),
            patch("asyncio.wait_for", AsyncMock(side_effect=TimeoutError)),
        ):
            ok, msg = await hub._run_shield(CONTAINER, DOMAIN, "allow")
        assert ok is False
        assert "timed out" in msg

    @pytest.mark.asyncio
    async def test_spawn_oserror_soft_fails(self) -> None:
        hub = ClearanceHub(shield_binary="/bin/true")
        with patch(
            "asyncio.create_subprocess_exec",
            AsyncMock(side_effect=OSError("exec failed")),
        ):
            ok, msg = await hub._run_shield(CONTAINER, DOMAIN, "allow")
        assert ok is False
        assert "spawn failed" in msg


# ── Reader-event relay (end-to-end internals) ─────────────────────────


class TestRelayReaderEvent:
    """Ingester-dict → typed event → live_verdicts + subscriber fan-out."""

    @pytest.mark.asyncio
    async def test_full_pending_event_lands_on_subscriber(self) -> None:
        hub = _hub()
        q: asyncio.Queue = asyncio.Queue(maxsize=4)
        hub._subscribers.add(q)
        await hub._relay_reader_event(
            {
                "type": "pending",
                "container": CONTAINER,
                "id": f"{CONTAINER}:1",
                "dest": DEST_IP,
                "port": 443,
                "proto": 6,
                "domain": DOMAIN,
            }
        )
        event = q.get_nowait()
        assert event.type == "connection_blocked"
        assert event.request_id == f"{CONTAINER}:1"
        # Authz binding recorded for the follow-up Verdict.
        assert f"{CONTAINER}:1" in hub._live_verdicts

    @pytest.mark.asyncio
    async def test_unknown_type_is_silently_dropped(self) -> None:
        hub = _hub()
        q: asyncio.Queue = asyncio.Queue(maxsize=4)
        hub._subscribers.add(q)
        await hub._relay_reader_event({"type": "unheard-of", "container": CONTAINER})
        assert q.empty()

    @pytest.mark.asyncio
    async def test_malformed_event_is_swallowed(self) -> None:
        """A missing required field (e.g. container) doesn't kill the ingester."""
        hub = _hub()
        q: asyncio.Queue = asyncio.Queue(maxsize=4)
        hub._subscribers.add(q)
        await hub._relay_reader_event({"type": "pending"})  # no container, no id
        assert q.empty()
