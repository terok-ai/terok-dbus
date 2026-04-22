# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for EventSubscriber — unified Shield1 subscription."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from dbus_fast import MessageType
from dbus_fast.message import Message

from terok_dbus._identity import ContainerIdentity
from terok_dbus._interfaces import (
    CLEARANCE_BUS_NAME,
    CLEARANCE_INTERFACE_NAME,
    CLEARANCE_OBJECT_PATH,
    SHIELD_BUS_NAME,
    SHIELD_INTERFACE_NAME,
    SHIELD_OBJECT_PATH,
)
from terok_dbus._subscriber import (
    _HINT_CONFIRMATION,
    _HINT_LIFECYCLE,
    _HINT_SECURITY_ALERT,
    EventSubscriber,
)
from tests.conftest import CONTAINER, DEST_IP, DOMAIN

_HUB_UNIQUE = ":1.77"
_REQUEST_ID = f"{CONTAINER}:1"


# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def mock_notifier() -> AsyncMock:
    """A mock satisfying the Notifier protocol."""
    notifier = AsyncMock()
    notifier.notify = AsyncMock(return_value=42)
    notifier.on_action = AsyncMock()
    return notifier


def _mock_bus() -> MagicMock:
    """A MessageBus double: AddMatch / RemoveMatch return Messages, call works."""
    bus = MagicMock()
    bus.add_message_handler = MagicMock()
    bus.remove_message_handler = MagicMock()
    bus.disconnect = MagicMock()
    reply = MagicMock(body=[])
    bus.call = AsyncMock(return_value=reply)
    return bus


def _connection_blocked_signal(
    request_id: str = _REQUEST_ID,
    *,
    container: str = CONTAINER,
    dest: str = DEST_IP,
    port: int = 443,
    proto: int = 6,
    domain: str = DOMAIN,
) -> Message:
    """Construct a Shield1.ConnectionBlocked signal as the reader would emit it."""
    return Message(
        message_type=MessageType.SIGNAL,
        sender=_HUB_UNIQUE,
        path=SHIELD_OBJECT_PATH,
        interface=SHIELD_INTERFACE_NAME,
        member="ConnectionBlocked",
        body=[container, request_id, dest, port, proto, domain],
    )


def _verdict_applied_signal(
    action: str = "allow",
    ok: bool = True,
    *,
    request_id: str = _REQUEST_ID,
    container: str = CONTAINER,
) -> Message:
    """Construct a Shield1.VerdictApplied signal as the hub would emit it."""
    return Message(
        message_type=MessageType.SIGNAL,
        sender=_HUB_UNIQUE,
        path=SHIELD_OBJECT_PATH,
        interface=SHIELD_INTERFACE_NAME,
        member="VerdictApplied",
        body=[container, request_id, action, ok],
    )


def _shield_signal(member: str, *, container: str = CONTAINER) -> Message:
    """Construct a parameter-less Shield1 signal (ShieldUp/Down/ContainerExited-ish)."""
    return Message(
        message_type=MessageType.SIGNAL,
        sender=_HUB_UNIQUE,
        path=SHIELD_OBJECT_PATH,
        interface=SHIELD_INTERFACE_NAME,
        member=member,
        body=[container],
    )


def _seed_subscriber(notifier: AsyncMock | MagicMock) -> tuple[EventSubscriber, MagicMock]:
    """Return a started-looking subscriber + its mock bus, ready for ``_on_message``."""
    bus = _mock_bus()
    sub = EventSubscriber(notifier, bus=bus)
    sub._bus = bus
    sub._shield_owner = _HUB_UNIQUE
    return sub, bus


# ── Lifecycle ─────────────────────────────────────────────────────────


class TestStart:
    """``start`` adds the three match rules and installs the handler."""

    @pytest.mark.asyncio
    async def test_adds_match_rules(self, mock_notifier: AsyncMock) -> None:
        bus = _mock_bus()
        sub = EventSubscriber(mock_notifier, bus=bus)
        with patch("terok_dbus._subscriber._add_match", AsyncMock()) as add_match:
            await sub.start()
        rules = [call.args[1] for call in add_match.call_args_list]
        assert any(SHIELD_INTERFACE_NAME in r for r in rules)
        assert any(CLEARANCE_INTERFACE_NAME in r for r in rules)
        assert any("NameOwnerChanged" in r and CLEARANCE_BUS_NAME in r for r in rules)
        bus.add_message_handler.assert_called_once()

    @pytest.mark.asyncio
    async def test_stop_cleans_up(self, mock_notifier: AsyncMock) -> None:
        bus = _mock_bus()
        sub = EventSubscriber(mock_notifier, bus=bus)
        with (
            patch("terok_dbus._subscriber._add_match", AsyncMock()),
            patch("terok_dbus._subscriber._remove_match", AsyncMock()) as remove_match,
        ):
            await sub.start()
            await sub.stop()
        assert remove_match.call_count == 4
        bus.remove_message_handler.assert_called_once()


# ── Signal dispatch ───────────────────────────────────────────────────


class TestShieldSignals:
    """ConnectionBlocked fires a notification; VerdictApplied updates it in place."""

    @pytest.mark.asyncio
    async def test_connection_blocked_creates_notification(self, mock_notifier: AsyncMock) -> None:
        bus = _mock_bus()
        sub = EventSubscriber(mock_notifier, bus=bus)
        sub._bus = bus
        sub._shield_owner = ":1.77"
        sub._on_message(_connection_blocked_signal())
        await asyncio.sleep(0)
        mock_notifier.notify.assert_awaited_once()
        assert _REQUEST_ID in sub._pending
        assert sub._pending[_REQUEST_ID].target == DOMAIN

    @pytest.mark.asyncio
    async def test_verdict_applied_updates_notification_in_place(
        self, mock_notifier: AsyncMock
    ) -> None:
        bus = _mock_bus()
        sub = EventSubscriber(mock_notifier, bus=bus)
        sub._bus = bus
        sub._shield_owner = _HUB_UNIQUE
        sub._on_message(_connection_blocked_signal())
        await asyncio.sleep(0)
        sub._on_message(_verdict_applied_signal(action="allow", ok=True))
        await asyncio.sleep(0)
        assert mock_notifier.notify.await_count == 2
        resolution = mock_notifier.notify.await_args_list[1]
        assert resolution.kwargs.get("replaces_id") == 42
        assert resolution.args[0] == f"Allowed: {DOMAIN}"
        assert resolution.kwargs["hints"] is _HINT_CONFIRMATION
        assert resolution.kwargs["timeout_ms"] == -1
        assert _REQUEST_ID not in sub._pending

    @pytest.mark.asyncio
    async def test_container_started_fires_lifecycle_notification(self) -> None:
        """ContainerStarted → low-urgency transient notification + lifecycle hook."""
        notifier = AsyncMock()
        notifier.notify = AsyncMock(return_value=42)
        notifier.on_container_started = MagicMock()
        bus = _mock_bus()
        sub = EventSubscriber(notifier, bus=bus)
        sub._shield_owner = ":1.77"
        started = Message(
            message_type=MessageType.SIGNAL,
            sender=":1.77",
            path=SHIELD_OBJECT_PATH,
            interface=SHIELD_INTERFACE_NAME,
            member="ContainerStarted",
            body=[CONTAINER],
        )
        sub._on_message(started)
        for _ in range(3):
            await asyncio.sleep(0)
        notifier.on_container_started.assert_called_once_with(CONTAINER)
        notifier.notify.assert_awaited_once()
        call = notifier.notify.await_args
        assert call.args[0].startswith("Container started:")
        assert call.kwargs["hints"] is _HINT_LIFECYCLE
        assert call.kwargs["timeout_ms"] == -1

    @pytest.mark.asyncio
    async def test_container_exited_fires_lifecycle_notification(self) -> None:
        """ContainerExited → low-urgency transient notification with the reason."""
        notifier = AsyncMock()
        notifier.notify = AsyncMock(return_value=42)
        notifier.on_container_exited = MagicMock()
        bus = _mock_bus()
        sub = EventSubscriber(notifier, bus=bus)
        sub._shield_owner = ":1.77"
        exited = Message(
            message_type=MessageType.SIGNAL,
            sender=":1.77",
            path=SHIELD_OBJECT_PATH,
            interface=SHIELD_INTERFACE_NAME,
            member="ContainerExited",
            body=[CONTAINER, "poststop"],
        )
        sub._on_message(exited)
        for _ in range(3):
            await asyncio.sleep(0)
        notifier.on_container_exited.assert_called_once_with(CONTAINER, "poststop")
        # notify fires for the lifecycle popup (the purge path only calls close()).
        lifecycle_calls = [
            c for c in notifier.notify.await_args_list if c.args[0].startswith("Container stopped:")
        ]
        assert len(lifecycle_calls) == 1
        assert "poststop" in lifecycle_calls[0].args[1]
        assert lifecycle_calls[0].kwargs["hints"] is _HINT_LIFECYCLE
        assert lifecycle_calls[0].kwargs["timeout_ms"] == -1

    @pytest.mark.asyncio
    async def test_non_signal_messages_are_ignored(self, mock_notifier: AsyncMock) -> None:
        sub = EventSubscriber(mock_notifier, bus=_mock_bus())
        non_signal = MagicMock(
            message_type=MessageType.METHOD_RETURN,
            interface=SHIELD_INTERFACE_NAME,
            path=SHIELD_OBJECT_PATH,
        )
        sub._on_message(non_signal)
        await asyncio.sleep(0)
        mock_notifier.notify.assert_not_called()

    @pytest.mark.parametrize(
        ("member", "hook"),
        [
            ("ShieldUp", "on_shield_up"),
            ("ShieldDown", "on_shield_down"),
            ("ShieldDownAll", "on_shield_down_all"),
        ],
    )
    @pytest.mark.asyncio
    async def test_shield_state_signals_forward_to_hooks(self, member: str, hook: str) -> None:
        """Each Shield* signal fires the matching optional hook on the notifier."""
        notifier = AsyncMock()
        setattr(notifier, hook, MagicMock())
        bus = _mock_bus()
        sub = EventSubscriber(notifier, bus=bus)
        sub._shield_owner = _HUB_UNIQUE
        msg = Message(
            message_type=MessageType.SIGNAL,
            sender=_HUB_UNIQUE,
            path=SHIELD_OBJECT_PATH,
            interface=SHIELD_INTERFACE_NAME,
            member=member,
            body=[CONTAINER],
        )
        sub._on_message(msg)
        await asyncio.sleep(0)
        getattr(notifier, hook).assert_called_once_with(CONTAINER)

    @pytest.mark.parametrize("member", ["ShieldDown", "ShieldDownAll"])
    @pytest.mark.asyncio
    async def test_shield_down_closes_pending_notifications(self, member: str) -> None:
        """ShieldDown drops pending blocks for the affected container."""
        notifier = AsyncMock()
        notifier.close = AsyncMock()
        # Explicitly pin the optional sync hooks so AsyncMock doesn't auto-generate
        # coroutine-returning attrs that never get awaited.
        notifier.on_shield_down = MagicMock()
        notifier.on_shield_down_all = MagicMock()
        bus = _mock_bus()
        sub = EventSubscriber(notifier, bus=bus)
        sub._shield_owner = _HUB_UNIQUE
        # Seed two pending blocks: one for *CONTAINER*, one for another.
        from terok_dbus._subscriber import _PendingBlock

        sub._pending[_REQUEST_ID] = _PendingBlock(
            notification_id=42,
            container=CONTAINER,
            request_id=_REQUEST_ID,
            target=DOMAIN,
        )
        sub._pending["other:1"] = _PendingBlock(
            notification_id=43,
            container="other",
            request_id="other:1",
            target=DOMAIN,
        )
        msg = Message(
            message_type=MessageType.SIGNAL,
            sender=_HUB_UNIQUE,
            path=SHIELD_OBJECT_PATH,
            interface=SHIELD_INTERFACE_NAME,
            member=member,
            body=[CONTAINER],
        )
        sub._on_message(msg)
        # Two scheduled coroutines (handler + lifecycle) — one sleep lets both run.
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        notifier.close.assert_awaited_once_with(42)
        assert _REQUEST_ID not in sub._pending
        assert "other:1" in sub._pending  # untouched — different container

    @pytest.mark.asyncio
    async def test_spoofed_shield_signal_is_dropped(self, mock_notifier: AsyncMock) -> None:
        """Once the hub owner is known, signals from other senders don't drive state."""
        bus = _mock_bus()
        sub = EventSubscriber(mock_notifier, bus=bus)
        sub._bus = bus
        sub._shield_owner = ":1.77"  # the legitimate hub
        spoofed = _connection_blocked_signal()
        spoofed.sender = ":1.999"  # unrelated peer
        sub._on_message(spoofed)
        await asyncio.sleep(0)
        mock_notifier.notify.assert_not_called()
        assert sub._pending == {}

    @pytest.mark.asyncio
    async def test_shield_signal_dropped_when_owner_unknown(self, mock_notifier: AsyncMock) -> None:
        """Pre-seed-owner signals (startup race / hub down) must be refused."""
        bus = _mock_bus()
        sub = EventSubscriber(mock_notifier, bus=bus)
        sub._bus = bus
        assert sub._shield_owner is None
        sub._on_message(_connection_blocked_signal())
        await asyncio.sleep(0)
        mock_notifier.notify.assert_not_called()
        assert sub._pending == {}

    @pytest.mark.asyncio
    async def test_name_owner_changed_tracks_shield_owner(self, mock_notifier: AsyncMock) -> None:
        """NameOwnerChanged events keep ``_shield_owner`` current."""
        from terok_dbus._interfaces import SHIELD_BUS_NAME

        sub = EventSubscriber(mock_notifier, bus=_mock_bus())
        sub._on_name_owner_changed(SHIELD_BUS_NAME, "", ":1.77")
        assert sub._shield_owner == ":1.77"
        sub._on_name_owner_changed(SHIELD_BUS_NAME, ":1.77", "")
        assert sub._shield_owner is None

    @pytest.mark.parametrize(
        ("member", "expected_title"),
        [
            ("ShieldDown", "Shield down:"),
            ("ShieldDownAll", "Shield full bypass:"),
        ],
    )
    @pytest.mark.asyncio
    async def test_shield_down_posts_security_alert(self, member: str, expected_title: str) -> None:
        """Manual shield drop fires a persistent critical notification."""
        notifier = AsyncMock()
        notifier.notify = AsyncMock(return_value=101)
        notifier.close = AsyncMock()
        notifier.on_shield_down = MagicMock()
        notifier.on_shield_down_all = MagicMock()
        bus = _mock_bus()
        sub = EventSubscriber(notifier, bus=bus)
        sub._shield_owner = _HUB_UNIQUE
        msg = Message(
            message_type=MessageType.SIGNAL,
            sender=_HUB_UNIQUE,
            path=SHIELD_OBJECT_PATH,
            interface=SHIELD_INTERFACE_NAME,
            member=member,
            body=[CONTAINER],
        )
        sub._on_message(msg)
        for _ in range(4):
            await asyncio.sleep(0)
        alert_calls = [
            c for c in notifier.notify.await_args_list if c.args[0].startswith(expected_title)
        ]
        assert len(alert_calls) == 1
        assert alert_calls[0].kwargs["hints"] is _HINT_SECURITY_ALERT
        assert alert_calls[0].kwargs["timeout_ms"] == -1
        assert sub._shield_down_notifs[CONTAINER] == 101

    @pytest.mark.asyncio
    async def test_shield_up_closes_matching_shield_down(self) -> None:
        """ShieldUp closes the tracked ShieldDown notification before confirming."""
        notifier = AsyncMock()
        notifier.notify = AsyncMock(return_value=202)
        notifier.close = AsyncMock()
        notifier.on_shield_up = MagicMock()
        bus = _mock_bus()
        sub = EventSubscriber(notifier, bus=bus)
        sub._shield_owner = _HUB_UNIQUE
        sub._shield_down_notifs[CONTAINER] = 55
        msg = Message(
            message_type=MessageType.SIGNAL,
            sender=_HUB_UNIQUE,
            path=SHIELD_OBJECT_PATH,
            interface=SHIELD_INTERFACE_NAME,
            member="ShieldUp",
            body=[CONTAINER],
        )
        sub._on_message(msg)
        for _ in range(3):
            await asyncio.sleep(0)
        notifier.close.assert_awaited_once_with(55)
        assert CONTAINER not in sub._shield_down_notifs
        notifier.notify.assert_awaited_once()
        call = notifier.notify.await_args
        assert call.args[0].startswith("Shield up:")
        # Confirmation (normal + transient), not LIFECYCLE — GNOME skips
        # the popup entirely at urgency=0, hiding a state change the
        # operator just caused.
        assert call.kwargs["hints"] is _HINT_CONFIRMATION
        assert call.kwargs["timeout_ms"] == -1


class TestTaskIdentityRendering:
    """Body + kwargs surface the task triple for terok-orchestrated containers.

    When the resolver returns an identity with ``project`` + ``task_id``
    populated, the notification body's first line switches from
    ``Container: …`` to ``Task: project/task_id · task_name``, and the
    five structured kwargs flow to the ``CallbackNotifier`` so the TUI
    can render them however it likes.  Empty project/task_id falls back
    to the existing container-name display — standalone executor runs
    shouldn't change shape.
    """

    _PROJECT = "alpaka3"
    _TASK_ID = "z71dr"
    _TASK_NAME = "fish-benchmark"
    _CONTAINER_NAME = "alpaka3-cli-z71dr"

    def _terok_identity(self) -> ContainerIdentity:
        return ContainerIdentity(
            container_name=self._CONTAINER_NAME,
            project=self._PROJECT,
            task_id=self._TASK_ID,
            task_name=self._TASK_NAME,
        )

    @pytest.mark.asyncio
    async def test_terok_identity_renders_task_triple_in_body(
        self, mock_notifier: AsyncMock
    ) -> None:
        sub, _ = _seed_subscriber(mock_notifier)
        sub._identity_resolver = MagicMock(return_value=self._terok_identity())

        sub._on_message(_connection_blocked_signal())
        for _ in range(3):
            await asyncio.sleep(0.01)

        call = mock_notifier.notify.await_args
        body_first_line = call.args[1].split("\n", 1)[0]
        assert body_first_line == f"Task: {self._PROJECT}/{self._TASK_ID} · {self._TASK_NAME}"

    @pytest.mark.asyncio
    async def test_terok_identity_surfaces_as_notify_kwargs(self, mock_notifier: AsyncMock) -> None:
        sub, _ = _seed_subscriber(mock_notifier)
        sub._identity_resolver = MagicMock(return_value=self._terok_identity())

        sub._on_message(_connection_blocked_signal())
        for _ in range(3):
            await asyncio.sleep(0.01)

        kwargs = mock_notifier.notify.await_args.kwargs
        assert kwargs["container_name"] == self._CONTAINER_NAME
        assert kwargs["project"] == self._PROJECT
        assert kwargs["task_id"] == self._TASK_ID
        assert kwargs["task_name"] == self._TASK_NAME

    @pytest.mark.asyncio
    async def test_standalone_identity_falls_back_to_container_line(
        self, mock_notifier: AsyncMock
    ) -> None:
        """Non-terok containers keep the ``Container: name`` body shape."""
        sub, _ = _seed_subscriber(mock_notifier)
        sub._identity_resolver = MagicMock(return_value=ContainerIdentity(container_name="ad-hoc"))

        sub._on_message(_connection_blocked_signal())
        for _ in range(3):
            await asyncio.sleep(0.01)

        body_first_line = mock_notifier.notify.await_args.args[1].split("\n", 1)[0]
        assert body_first_line == "Container: ad-hoc"

    @pytest.mark.asyncio
    async def test_missing_task_name_still_shows_task_line(self, mock_notifier: AsyncMock) -> None:
        """Rename in flight or YAML unreadable → task triple without trailing name."""
        sub, _ = _seed_subscriber(mock_notifier)
        sub._identity_resolver = MagicMock(
            return_value=ContainerIdentity(
                container_name=self._CONTAINER_NAME,
                project=self._PROJECT,
                task_id=self._TASK_ID,
            )
        )

        sub._on_message(_connection_blocked_signal())
        for _ in range(3):
            await asyncio.sleep(0.01)

        body_first_line = mock_notifier.notify.await_args.args[1].split("\n", 1)[0]
        assert body_first_line == f"Task: {self._PROJECT}/{self._TASK_ID}"


# ── Verdict routing ───────────────────────────────────────────────────


class TestLiveBlockDedup:
    """Re-blocks of the same ``(container, domain-or-dest)`` reuse one prompt.

    The reader's 30-second window isn't the only source of duplicates;
    every re-attempt past that window, or any re-emit after the reader
    restarts, fires another ``ConnectionBlocked``.  Until the operator
    clicks, stacking prompts is noise — the notifier must collapse them
    via ``replaces_id``.
    """

    @pytest.mark.asyncio
    async def test_second_block_same_domain_reuses_notification(
        self, mock_notifier: AsyncMock
    ) -> None:
        sub, _ = _seed_subscriber(mock_notifier)

        sub._on_message(_connection_blocked_signal(request_id=f"{CONTAINER}:1"))
        await asyncio.sleep(0)
        sub._on_message(_connection_blocked_signal(request_id=f"{CONTAINER}:2"))
        await asyncio.sleep(0)

        assert mock_notifier.notify.await_count == 2
        first_call, second_call = mock_notifier.notify.await_args_list
        assert first_call.kwargs.get("replaces_id", 0) == 0
        assert second_call.kwargs.get("replaces_id") == 42
        assert f"{CONTAINER}:1" not in sub._pending
        assert f"{CONTAINER}:2" in sub._pending

    @pytest.mark.asyncio
    async def test_repeat_blocks_surface_counter_in_body(self, mock_notifier: AsyncMock) -> None:
        """Body gains a ``Blocked N times since HH:MM:SS`` line from the second hit on."""
        sub, _ = _seed_subscriber(mock_notifier)

        sub._on_message(_connection_blocked_signal(request_id=f"{CONTAINER}:1"))
        await asyncio.sleep(0)
        sub._on_message(_connection_blocked_signal(request_id=f"{CONTAINER}:2"))
        await asyncio.sleep(0)
        sub._on_message(_connection_blocked_signal(request_id=f"{CONTAINER}:3"))
        await asyncio.sleep(0)

        bodies = [call.args[1] for call in mock_notifier.notify.await_args_list]
        # First body has no counter; subsequent ones do, with an ascending count.
        assert "Blocked" not in bodies[0]
        assert "Blocked 2 times since" in bodies[1]
        assert "Blocked 3 times since" in bodies[2]
        # The timestamp is stable across the burst — all bodies share the same HH:MM:SS.
        first_ts = bodies[1].rsplit(" since ", 1)[1]
        third_ts = bodies[2].rsplit(" since ", 1)[1]
        assert first_ts == third_ts

    @pytest.mark.asyncio
    async def test_different_domain_creates_second_prompt(self, mock_notifier: AsyncMock) -> None:
        sub, _ = _seed_subscriber(mock_notifier)

        sub._on_message(_connection_blocked_signal(request_id=f"{CONTAINER}:1"))
        await asyncio.sleep(0)
        sub._on_message(
            _connection_blocked_signal(
                request_id=f"{CONTAINER}:2",
                dest="198.51.100.9",
                domain="other.example.net",
            )
        )
        await asyncio.sleep(0)

        assert mock_notifier.notify.await_count == 2
        _, second_call = mock_notifier.notify.await_args_list
        assert second_call.kwargs.get("replaces_id", 0) == 0
        assert f"{CONTAINER}:1" in sub._pending
        assert f"{CONTAINER}:2" in sub._pending

    @pytest.mark.asyncio
    async def test_different_container_same_domain_creates_second_prompt(
        self, mock_notifier: AsyncMock
    ) -> None:
        sub, _ = _seed_subscriber(mock_notifier)

        sub._on_message(_connection_blocked_signal(request_id=f"{CONTAINER}:1"))
        await asyncio.sleep(0)
        sub._on_message(
            _connection_blocked_signal(
                request_id="other-sandbox:1",
                container="other-sandbox",
            )
        )
        await asyncio.sleep(0)

        assert mock_notifier.notify.await_count == 2
        _, second_call = mock_notifier.notify.await_args_list
        assert second_call.kwargs.get("replaces_id", 0) == 0

    @pytest.mark.asyncio
    async def test_empty_domain_dedups_on_destination_ip(self, mock_notifier: AsyncMock) -> None:
        sub, _ = _seed_subscriber(mock_notifier)

        sub._on_message(_connection_blocked_signal(request_id=f"{CONTAINER}:1", domain=""))
        await asyncio.sleep(0)
        sub._on_message(_connection_blocked_signal(request_id=f"{CONTAINER}:2", domain=""))
        await asyncio.sleep(0)

        assert mock_notifier.notify.await_count == 2
        _, second_call = mock_notifier.notify.await_args_list
        assert second_call.kwargs.get("replaces_id") == 42

    @pytest.mark.asyncio
    async def test_verdict_applied_frees_live_slot(self, mock_notifier: AsyncMock) -> None:
        sub, _ = _seed_subscriber(mock_notifier)

        sub._on_message(_connection_blocked_signal(request_id=f"{CONTAINER}:1"))
        await asyncio.sleep(0)
        sub._on_message(_verdict_applied_signal(request_id=f"{CONTAINER}:1"))
        await asyncio.sleep(0)
        sub._on_message(_connection_blocked_signal(request_id=f"{CONTAINER}:3"))
        await asyncio.sleep(0)

        *_, third_call = mock_notifier.notify.await_args_list
        assert third_call.kwargs.get("replaces_id", 0) == 0

    @pytest.mark.asyncio
    async def test_click_on_reused_notification_routes_to_latest_request(
        self, mock_notifier: AsyncMock
    ) -> None:
        """Click on the reused popup must route the verdict to the latest request_id.

        The whole point of dedup is that the surviving popup represents
        the *current* block the shield is enforcing — the ``on_action``
        closure on the replaced notification must close over the *new*
        request_id, not the superseded one.
        """
        sub, bus = _seed_subscriber(mock_notifier)

        first_rid = f"{CONTAINER}:1"
        second_rid = f"{CONTAINER}:2"

        sub._on_message(_connection_blocked_signal(request_id=first_rid))
        await asyncio.sleep(0)
        sub._on_message(_connection_blocked_signal(request_id=second_rid))
        await asyncio.sleep(0)

        assert mock_notifier.notify.await_args_list[1].kwargs["replaces_id"] == 42
        assert second_rid in sub._pending and first_rid not in sub._pending

        latest_callback = mock_notifier.on_action.await_args_list[1][0][1]
        latest_callback("allow")
        await asyncio.sleep(0)

        verdict_msgs = [
            m
            for m in (c.args[0] for c in bus.call.await_args_list if c.args)
            if m.member == "Verdict"
        ]
        assert len(verdict_msgs) == 1
        assert verdict_msgs[0].body == [CONTAINER, second_rid, DOMAIN, "allow"]

    @pytest.mark.asyncio
    async def test_notify_failure_preserves_superseded_pending_entry(
        self, mock_notifier: AsyncMock
    ) -> None:
        """A raising ``notify`` must leave the prior pending record intact.

        Dropping it eagerly would orphan the on-screen popup — a later
        ``VerdictApplied`` or ``ShieldDown`` for the first request_id
        would have no handle to close or update it.
        """
        sub, _ = _seed_subscriber(mock_notifier)

        first_rid = f"{CONTAINER}:1"
        second_rid = f"{CONTAINER}:2"

        sub._on_message(_connection_blocked_signal(request_id=first_rid))
        await asyncio.sleep(0)
        mock_notifier.notify.side_effect = RuntimeError("bus disconnected")
        sub._on_message(_connection_blocked_signal(request_id=second_rid))
        for _ in range(3):
            await asyncio.sleep(0)

        assert first_rid in sub._pending
        assert second_rid not in sub._pending
        assert sub._pending[first_rid].notification_id == 42

    @pytest.mark.asyncio
    async def test_shield_down_frees_live_slot(self) -> None:
        notifier = AsyncMock()
        notifier.notify.return_value = 42
        notifier.close = AsyncMock()
        notifier.on_shield_down = MagicMock()
        sub, _ = _seed_subscriber(notifier)

        sub._on_message(_connection_blocked_signal(request_id=f"{CONTAINER}:1"))
        await asyncio.sleep(0)

        sub._on_message(_shield_signal("ShieldDown"))
        for _ in range(3):
            await asyncio.sleep(0)

        sub._on_message(_connection_blocked_signal(request_id=f"{CONTAINER}:2"))
        await asyncio.sleep(0)
        *_, last_call = notifier.notify.await_args_list
        assert last_call.kwargs.get("replaces_id", 0) == 0

    @pytest.mark.asyncio
    async def test_container_exited_purges_pending_and_closes_popup(self) -> None:
        """A dying container without a trailing ShieldDown must still release state.

        Clean stops usually emit ``ShieldDown`` first, but a kill or OOM
        leaves only ``ContainerExited`` — without cleanup here ``_pending``
        leaks and the desktop popup hangs around.
        """
        notifier = AsyncMock()
        notifier.notify.return_value = 42
        notifier.close = AsyncMock()
        notifier.on_container_exited = MagicMock()
        sub, _ = _seed_subscriber(notifier)

        sub._on_message(_connection_blocked_signal(request_id=f"{CONTAINER}:1"))
        await asyncio.sleep(0)
        assert f"{CONTAINER}:1" in sub._pending

        exited = Message(
            message_type=MessageType.SIGNAL,
            sender=_HUB_UNIQUE,
            path=SHIELD_OBJECT_PATH,
            interface=SHIELD_INTERFACE_NAME,
            member="ContainerExited",
            body=[CONTAINER, "poststop"],
        )
        sub._on_message(exited)
        for _ in range(3):
            await asyncio.sleep(0)

        notifier.close.assert_awaited_once_with(42)
        assert f"{CONTAINER}:1" not in sub._pending

    @pytest.mark.asyncio
    async def test_container_exited_closes_tracked_shield_down_popup(self) -> None:
        """A dying container drops its ``_shield_down_notifs`` entry too.

        The "Shield down: X" popup is persistent; leaving it alive after
        the container is gone would mislead the operator and set up a
        stale ``replaces_id`` reuse for a future same-named container.
        """
        notifier = AsyncMock()
        notifier.notify.return_value = 42
        notifier.close = AsyncMock()
        notifier.on_container_exited = MagicMock()
        sub, _ = _seed_subscriber(notifier)
        sub._shield_down_notifs[CONTAINER] = 77

        exited = Message(
            message_type=MessageType.SIGNAL,
            sender=_HUB_UNIQUE,
            path=SHIELD_OBJECT_PATH,
            interface=SHIELD_INTERFACE_NAME,
            member="ContainerExited",
            body=[CONTAINER, "poststop"],
        )
        sub._on_message(exited)
        for _ in range(3):
            await asyncio.sleep(0)

        close_ids = {call.args[0] for call in notifier.close.await_args_list}
        assert 77 in close_ids
        assert CONTAINER not in sub._shield_down_notifs
        notifier.on_container_exited.assert_called_once_with(CONTAINER, "poststop")


class TestSendVerdict:
    """_send_verdict targets the hub's well-known bus name, not a per-container sender."""

    @pytest.mark.asyncio
    async def test_verdict_call_addresses_hub(self, mock_notifier: AsyncMock) -> None:
        bus = _mock_bus()
        sub = EventSubscriber(mock_notifier, bus=bus)
        sub._bus = bus
        await sub._send_verdict(CONTAINER, _REQUEST_ID, DEST_IP, "allow")
        assert bus.call.await_count == 1
        msg = bus.call.await_args[0][0]
        assert msg.destination == SHIELD_BUS_NAME
        assert msg.member == "Verdict"
        assert msg.body == [CONTAINER, _REQUEST_ID, DEST_IP, "allow"]

    @pytest.mark.asyncio
    async def test_action_callback_is_wired_on_block(self, mock_notifier: AsyncMock) -> None:
        """``Verdict`` carries the cached domain when the signal had one."""
        sub, bus = _seed_subscriber(mock_notifier)
        sub._on_message(_connection_blocked_signal())
        await asyncio.sleep(0)
        mock_notifier.on_action.assert_awaited_once()
        action_cb = mock_notifier.on_action.await_args[0][1]
        action_cb("allow")
        await asyncio.sleep(0)
        assert bus.call.await_count >= 1
        msg = bus.call.await_args[0][0]
        assert msg.member == "Verdict"
        assert msg.body == [CONTAINER, _REQUEST_ID, DOMAIN, "allow"]

    @pytest.mark.asyncio
    async def test_action_callback_falls_back_to_dest_when_signal_has_no_domain(
        self, mock_notifier: AsyncMock
    ) -> None:
        """Empty domain → ``Verdict`` falls back to the destination IP."""
        sub, bus = _seed_subscriber(mock_notifier)
        sub._on_message(_connection_blocked_signal(domain=""))
        await asyncio.sleep(0)
        action_cb = mock_notifier.on_action.await_args[0][1]
        action_cb("allow")
        await asyncio.sleep(0)
        msg = bus.call.await_args[0][0]
        assert msg.body == [CONTAINER, _REQUEST_ID, DEST_IP, "allow"]

    @pytest.mark.asyncio
    async def test_signal_with_empty_target_is_dropped(self, mock_notifier: AsyncMock) -> None:
        """Malformed signal with neither dest nor domain → no notification, no verdict.

        Forwarding an empty string would poison shield's ``allow_domain``.
        """
        sub, _ = _seed_subscriber(mock_notifier)
        sub._on_message(_connection_blocked_signal(dest="", domain=""))
        await asyncio.sleep(0)
        mock_notifier.notify.assert_not_called()
        assert sub._pending == {}


# ── Name resolver off-thread + error handling ─────────────────────────


class TestResolveIdentity:
    """``_resolve_identity`` offloads the resolver and fails soft."""

    @pytest.mark.asyncio
    async def test_returns_empty_when_resolver_absent(self, mock_notifier: AsyncMock) -> None:
        """No injected resolver → empty identity, no thread spawned."""
        sub = EventSubscriber(mock_notifier, bus=_mock_bus())
        assert await sub._resolve_identity(CONTAINER) == ContainerIdentity()

    @pytest.mark.asyncio
    async def test_returns_empty_on_empty_container(self, mock_notifier: AsyncMock) -> None:
        """Defensive short-circuit for empty container IDs from bad wire data."""
        resolver = MagicMock(return_value=ContainerIdentity(container_name="should-not-be-called"))
        sub = EventSubscriber(mock_notifier, bus=_mock_bus(), identity_resolver=resolver)
        assert await sub._resolve_identity("") == ContainerIdentity()
        resolver.assert_not_called()

    @pytest.mark.asyncio
    async def test_resolves_via_to_thread(self, mock_notifier: AsyncMock) -> None:
        """Resolver runs through ``asyncio.to_thread`` so the loop stays free."""
        expected = ContainerIdentity(container_name="my-task")
        resolver = MagicMock(return_value=expected)
        sub = EventSubscriber(mock_notifier, bus=_mock_bus(), identity_resolver=resolver)
        with patch("terok_dbus._subscriber.asyncio.to_thread") as to_thread:

            async def fake(func, arg):
                return func(arg)

            to_thread.side_effect = fake
            result = await sub._resolve_identity(CONTAINER)
        assert result == expected
        to_thread.assert_awaited_once_with(resolver, CONTAINER)

    @pytest.mark.asyncio
    async def test_returns_empty_on_resolver_exception(self, mock_notifier: AsyncMock) -> None:
        """A resolver that raises can't knock notifications off the rails."""
        resolver = MagicMock(side_effect=RuntimeError("podman unreachable"))
        sub = EventSubscriber(mock_notifier, bus=_mock_bus(), identity_resolver=resolver)
        assert await sub._resolve_identity(CONTAINER) == ContainerIdentity()


# ── Clearance1 routing (legacy path) ──────────────────────────────────


class TestClearanceNameTracking:
    """NameOwnerChanged for the Clearance service updates the router."""

    def test_owner_appearing_is_remembered(self, mock_notifier: AsyncMock) -> None:
        sub = EventSubscriber(mock_notifier, bus=_mock_bus())
        sub._on_name_owner_changed(CLEARANCE_BUS_NAME, "", ":1.99")
        assert sub._clearance_senders[CLEARANCE_BUS_NAME] == ":1.99"

    def test_owner_disappearing_is_forgotten(self, mock_notifier: AsyncMock) -> None:
        sub = EventSubscriber(mock_notifier, bus=_mock_bus())
        sub._clearance_senders[CLEARANCE_BUS_NAME] = ":1.99"
        sub._on_name_owner_changed(CLEARANCE_BUS_NAME, ":1.99", "")
        assert CLEARANCE_BUS_NAME not in sub._clearance_senders

    def test_non_clearance_names_ignored(self, mock_notifier: AsyncMock) -> None:
        sub = EventSubscriber(mock_notifier, bus=_mock_bus())
        sub._on_name_owner_changed("org.freedesktop.Other", "", ":1.50")
        assert sub._clearance_senders == {}


class TestClearanceSignals:
    """Clearance1 RequestReceived requires a known sender; resolution updates in place."""

    @pytest.mark.asyncio
    async def test_unknown_sender_is_ignored(self, mock_notifier: AsyncMock) -> None:
        sub = EventSubscriber(mock_notifier, bus=_mock_bus())
        msg = Message(
            message_type=MessageType.SIGNAL,
            sender=":1.99",
            path=CLEARANCE_OBJECT_PATH,
            interface=CLEARANCE_INTERFACE_NAME,
            member="RequestReceived",
            body=["rid", "proj", "task", DEST_IP, 443, "reason"],
        )
        sub._on_message(msg)
        await asyncio.sleep(0)
        mock_notifier.notify.assert_not_called()

    @pytest.mark.asyncio
    async def test_known_sender_fires_notification(self, mock_notifier: AsyncMock) -> None:
        bus = _mock_bus()
        sub = EventSubscriber(mock_notifier, bus=bus)
        sub._clearance_senders[CLEARANCE_BUS_NAME] = ":1.99"
        msg = Message(
            message_type=MessageType.SIGNAL,
            sender=":1.99",
            path=CLEARANCE_OBJECT_PATH,
            interface=CLEARANCE_INTERFACE_NAME,
            member="RequestReceived",
            body=["rid", "proj", "task", DEST_IP, 443, "reason"],
        )
        sub._on_message(msg)
        await asyncio.sleep(0)
        mock_notifier.notify.assert_awaited_once()
