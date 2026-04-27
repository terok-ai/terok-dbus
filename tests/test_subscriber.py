# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for [`EventSubscriber`][terok_clearance.EventSubscriber] — the notification-rendering layer.

Exercises the dispatch + state machine in isolation by mocking the
[`ClearanceClient`][terok_clearance.ClearanceClient] transport.  Real varlink round-trips live in
``test_client.py``; here we feed [`ClearanceEvent`][terok_clearance.ClearanceEvent] instances
straight into `EventSubscriber._on_event` and inspect the
notifier it drives.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from terok_clearance.client.subscriber import (
    _HINT_BLOCK_PENDING,
    _HINT_CONFIRMATION,
    _HINT_LIFECYCLE,
    _HINT_SECURITY_ALERT,
    EventSubscriber,
)
from terok_clearance.domain.events import ClearanceEvent
from terok_clearance.domain.identity import ContainerIdentity

from .conftest import CONTAINER, DEST_IP, DOMAIN

# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def mock_notifier() -> AsyncMock:
    """Notifier stub — notify() returns a monotonic id, close() is a no-op."""
    notifier = AsyncMock()
    notifier.notify = AsyncMock(return_value=42)
    notifier.on_action = AsyncMock()
    notifier.close = AsyncMock()
    return notifier


@pytest.fixture
def subscriber(mock_notifier: AsyncMock) -> EventSubscriber:
    """A subscriber with a mocked client — no actual varlink traffic."""
    client = MagicMock()
    client.start = AsyncMock()
    client.stop = AsyncMock()
    client.verdict = AsyncMock(return_value=True)
    return EventSubscriber(mock_notifier, client=client)


def _blocked(
    request_id: str = f"{CONTAINER}:1",
    *,
    container: str = CONTAINER,
    dest: str = DEST_IP,
    domain: str = DOMAIN,
    port: int = 443,
    proto: int = 6,
) -> ClearanceEvent:
    """Build a ``connection_blocked`` event with sensible defaults."""
    return ClearanceEvent(
        type="connection_blocked",
        container=container,
        request_id=request_id,
        dest=dest,
        port=port,
        proto=proto,
        domain=domain,
    )


# ── connection_blocked ────────────────────────────────────────────────


class TestConnectionBlocked:
    """First-block rendering and its per-event side effects."""

    @pytest.mark.asyncio
    async def test_first_block_fires_a_prompt(
        self, subscriber: EventSubscriber, mock_notifier: AsyncMock
    ) -> None:
        """Summary + body + hints match the spec for a brand-new block."""
        await subscriber._on_event(_blocked())
        mock_notifier.notify.assert_awaited_once()
        call = mock_notifier.notify.await_args
        assert call.args[0] == f"Blocked: {DOMAIN}:443"
        assert "TCP" in call.args[1]
        assert call.kwargs["hints"] is _HINT_BLOCK_PENDING
        assert call.kwargs["timeout_ms"] == 0
        # No replaces_id on the first block (freedesktop spec: 0 = fresh).
        assert call.kwargs.get("replaces_id", 0) == 0

    @pytest.mark.asyncio
    async def test_first_block_records_pending_state(self, subscriber: EventSubscriber) -> None:
        await subscriber._on_event(_blocked())
        assert f"{CONTAINER}:1" in subscriber._pending

    @pytest.mark.asyncio
    async def test_empty_target_event_is_dropped(
        self, subscriber: EventSubscriber, mock_notifier: AsyncMock
    ) -> None:
        """Malformed event (empty dest AND domain) produces no notification."""
        await subscriber._on_event(_blocked(dest="", domain=""))
        mock_notifier.notify.assert_not_called()

    @pytest.mark.asyncio
    async def test_second_block_same_target_reuses_notification(
        self, subscriber: EventSubscriber, mock_notifier: AsyncMock
    ) -> None:
        """A repeat block for the same (container, target) updates the live popup."""
        await subscriber._on_event(_blocked(f"{CONTAINER}:1"))
        await subscriber._on_event(_blocked(f"{CONTAINER}:2"))
        assert mock_notifier.notify.await_count == 2
        second = mock_notifier.notify.await_args_list[1]
        assert second.kwargs["replaces_id"] == 42
        assert "Blocked 2 times since" in second.args[1]
        # Only the latest request_id survives in _pending.
        assert f"{CONTAINER}:1" not in subscriber._pending
        assert f"{CONTAINER}:2" in subscriber._pending

    @pytest.mark.asyncio
    async def test_different_target_creates_distinct_popup(
        self, subscriber: EventSubscriber, mock_notifier: AsyncMock
    ) -> None:
        """Blocks on distinct domains never dedup."""
        await subscriber._on_event(_blocked(f"{CONTAINER}:1", domain="a.example.net"))
        await subscriber._on_event(_blocked(f"{CONTAINER}:2", domain="b.example.net"))
        # Both get fresh notifications (replaces_id==0 on both).
        assert mock_notifier.notify.await_count == 2
        for call in mock_notifier.notify.await_args_list:
            assert call.kwargs.get("replaces_id", 0) == 0


# ── verdict_applied ───────────────────────────────────────────────────


class TestVerdictApplied:
    """Outcome rendering + in-place replacement via replaces_id."""

    @pytest.mark.asyncio
    async def test_success_renders_confirmation(
        self, subscriber: EventSubscriber, mock_notifier: AsyncMock
    ) -> None:
        await subscriber._on_event(_blocked())
        mock_notifier.notify.reset_mock()
        await subscriber._on_event(
            ClearanceEvent(
                type="verdict_applied",
                container=CONTAINER,
                request_id=f"{CONTAINER}:1",
                action="allow",
                ok=True,
            )
        )
        call = mock_notifier.notify.await_args
        assert call.args[0] == f"Allowed: {DOMAIN}"
        assert call.kwargs["hints"] is _HINT_CONFIRMATION
        assert call.kwargs["replaces_id"] == 42
        # Pending entry released on verdict.
        assert f"{CONTAINER}:1" not in subscriber._pending

    @pytest.mark.asyncio
    async def test_failure_renders_security_alert(
        self, subscriber: EventSubscriber, mock_notifier: AsyncMock
    ) -> None:
        """ok=false flips to critical hints + 'failed' verb."""
        await subscriber._on_event(_blocked())
        mock_notifier.notify.reset_mock()
        await subscriber._on_event(
            ClearanceEvent(
                type="verdict_applied",
                container=CONTAINER,
                request_id=f"{CONTAINER}:1",
                action="allow",
                ok=False,
            )
        )
        call = mock_notifier.notify.await_args
        assert call.args[0] == f"Allow failed: {DOMAIN}"
        assert call.kwargs["hints"] is _HINT_SECURITY_ALERT

    @pytest.mark.asyncio
    async def test_no_pending_is_silent(
        self, subscriber: EventSubscriber, mock_notifier: AsyncMock
    ) -> None:
        """A verdict_applied for a request we didn't see produces no popup."""
        await subscriber._on_event(
            ClearanceEvent(
                type="verdict_applied",
                container=CONTAINER,
                request_id="ghost:9",
                action="allow",
                ok=True,
            )
        )
        mock_notifier.notify.assert_not_called()


# ── shield_down / shield_up ───────────────────────────────────────────


class TestShieldState:
    """Persistent ShieldDown alerts get retired on ShieldUp."""

    @pytest.mark.parametrize(
        ("member", "expected_title", "body_hint"),
        [
            ("shield_down", "Shield down: ", "bypassed"),
            ("shield_down_all", "Shield full bypass: ", "fully disabled"),
        ],
    )
    @pytest.mark.asyncio
    async def test_shield_down_posts_security_alert(
        self,
        subscriber: EventSubscriber,
        mock_notifier: AsyncMock,
        member: str,
        expected_title: str,
        body_hint: str,
    ) -> None:
        await subscriber._on_event(ClearanceEvent(type=member, container=CONTAINER))
        # The _notify_shield_down dispatch is scheduled as a background task;
        # yield the loop so it gets a chance to run.
        for _ in range(3):
            await asyncio.sleep(0)
        alert_calls = [
            c for c in mock_notifier.notify.await_args_list if c.args[0].startswith(expected_title)
        ]
        assert len(alert_calls) == 1
        assert body_hint in alert_calls[0].args[1]
        assert alert_calls[0].kwargs["hints"] is _HINT_SECURITY_ALERT
        assert alert_calls[0].kwargs["timeout_ms"] == -1
        # Tracked so a later ShieldUp can close it.
        assert subscriber._shield_down_notifs[CONTAINER] == 42

    @pytest.mark.asyncio
    async def test_shield_up_closes_tracked_down_popup(
        self, subscriber: EventSubscriber, mock_notifier: AsyncMock
    ) -> None:
        subscriber._shield_down_notifs[CONTAINER] = 77
        await subscriber._on_event(ClearanceEvent(type="shield_up", container=CONTAINER))
        for _ in range(3):
            await asyncio.sleep(0)
        mock_notifier.close.assert_awaited_once_with(77)
        assert CONTAINER not in subscriber._shield_down_notifs
        # Followed by a brief confirmation.
        confirmation = [
            c for c in mock_notifier.notify.await_args_list if c.args[0].startswith("Shield up:")
        ]
        assert len(confirmation) == 1
        assert confirmation[0].kwargs["hints"] is _HINT_CONFIRMATION

    @pytest.mark.asyncio
    async def test_shield_down_purges_pending_blocks(
        self, subscriber: EventSubscriber, mock_notifier: AsyncMock
    ) -> None:
        """Bypass means in-flight prompts are stale; drop them."""
        await subscriber._on_event(_blocked())
        assert f"{CONTAINER}:1" in subscriber._pending
        await subscriber._on_event(ClearanceEvent(type="shield_down", container=CONTAINER))
        for _ in range(3):
            await asyncio.sleep(0)
        assert f"{CONTAINER}:1" not in subscriber._pending


# ── container lifecycle ───────────────────────────────────────────────


class TestContainerLifecycle:
    """ContainerStarted/Exited fire low-urgency transient popups."""

    @pytest.mark.asyncio
    async def test_container_started_renders_lifecycle_popup(
        self, subscriber: EventSubscriber, mock_notifier: AsyncMock
    ) -> None:
        await subscriber._on_event(ClearanceEvent(type="container_started", container=CONTAINER))
        for _ in range(3):
            await asyncio.sleep(0)
        started = [
            c
            for c in mock_notifier.notify.await_args_list
            if c.args[0].startswith("Container started:")
        ]
        assert len(started) == 1
        assert started[0].kwargs["hints"] is _HINT_LIFECYCLE
        assert started[0].kwargs["timeout_ms"] == -1

    @pytest.mark.asyncio
    async def test_container_exited_renders_with_reason(
        self, subscriber: EventSubscriber, mock_notifier: AsyncMock
    ) -> None:
        await subscriber._on_event(
            ClearanceEvent(type="container_exited", container=CONTAINER, reason="poststop")
        )
        for _ in range(3):
            await asyncio.sleep(0)
        stopped = [
            c
            for c in mock_notifier.notify.await_args_list
            if c.args[0].startswith("Container stopped:")
        ]
        assert len(stopped) == 1
        assert "poststop" in stopped[0].args[1]

    @pytest.mark.asyncio
    async def test_container_exited_closes_tracked_shield_down_popup(
        self, subscriber: EventSubscriber, mock_notifier: AsyncMock
    ) -> None:
        """A dying container drops its ShieldDown popup too — no ghost alerts."""
        subscriber._shield_down_notifs[CONTAINER] = 77
        await subscriber._on_event(
            ClearanceEvent(type="container_exited", container=CONTAINER, reason="poststop")
        )
        for _ in range(3):
            await asyncio.sleep(0)
        close_ids = {c.args[0] for c in mock_notifier.close.await_args_list}
        assert 77 in close_ids
        assert CONTAINER not in subscriber._shield_down_notifs


# ── verdict routing ───────────────────────────────────────────────────


class TestVerdictRouting:
    """Action callback → ClearanceClient.verdict() dispatch."""

    @pytest.mark.asyncio
    async def test_action_callback_sends_verdict_via_client(
        self, subscriber: EventSubscriber, mock_notifier: AsyncMock
    ) -> None:
        """Clicking Allow on a notification routes through the transport."""
        await subscriber._on_event(_blocked())
        # on_action registers a callback; pick it off the mock.
        action_cb = mock_notifier.on_action.await_args.args[1]
        action_cb("allow")
        # Let the dispatched verdict coroutine run.
        for _ in range(3):
            await asyncio.sleep(0)
        subscriber._client.verdict.assert_awaited_once_with(
            CONTAINER, f"{CONTAINER}:1", DOMAIN, "allow"
        )


# ── identity resolution ───────────────────────────────────────────────


class TestIdentityResolution:
    """Injected resolver populates terok-aware notification bodies."""

    @pytest.mark.asyncio
    async def test_task_identity_surfaces_in_body(self, mock_notifier: AsyncMock) -> None:
        """A resolved project/task_id renders as 'Task: project/task_id · name'."""
        resolver = MagicMock(
            return_value=ContainerIdentity(
                container_name="sandbox-alpha-1",
                project="warp-core",
                task_id="t42",
                task_name="build",
            )
        )
        sub = EventSubscriber(
            mock_notifier,
            client=MagicMock(start=AsyncMock(), verdict=AsyncMock(return_value=True)),
            identity_resolver=resolver,
        )
        await sub._on_event(_blocked())
        call = mock_notifier.notify.await_args
        assert "warp-core/t42" in call.args[1]
        assert "build" in call.args[1]

    @pytest.mark.asyncio
    async def test_resolver_exception_falls_back_gracefully(self, mock_notifier: AsyncMock) -> None:
        resolver = MagicMock(side_effect=RuntimeError("podman fell over"))
        sub = EventSubscriber(
            mock_notifier,
            client=MagicMock(start=AsyncMock(), verdict=AsyncMock(return_value=True)),
            identity_resolver=resolver,
        )
        await sub._on_event(_blocked())
        # Still renders the popup with the container ID fallback.
        call = mock_notifier.notify.await_args
        assert CONTAINER in call.args[1]
