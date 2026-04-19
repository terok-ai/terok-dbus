# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for EventSubscriber — unified Shield1 subscription."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from dbus_fast import MessageType
from dbus_fast.message import Message

from terok_dbus._interfaces import (
    CLEARANCE_BUS_NAME,
    CLEARANCE_INTERFACE_NAME,
    CLEARANCE_OBJECT_PATH,
    SHIELD_BUS_NAME,
    SHIELD_INTERFACE_NAME,
    SHIELD_OBJECT_PATH,
)
from terok_dbus._subscriber import EventSubscriber
from tests.conftest import CONTAINER, DEST_IP, DOMAIN

_HUB_UNIQUE = ":1.42"
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


def _connection_blocked_signal(request_id: str = _REQUEST_ID) -> Message:
    """Construct a Shield1.ConnectionBlocked signal as the reader would emit it."""
    return Message(
        message_type=MessageType.SIGNAL,
        sender=":1.77",
        path=SHIELD_OBJECT_PATH,
        interface=SHIELD_INTERFACE_NAME,
        member="ConnectionBlocked",
        body=[CONTAINER, request_id, DEST_IP, 443, 6, DOMAIN],
    )


def _verdict_applied_signal(action: str = "allow", ok: bool = True) -> Message:
    """Construct a Shield1.VerdictApplied signal as the hub would emit it."""
    return Message(
        message_type=MessageType.SIGNAL,
        sender=_HUB_UNIQUE,
        path=SHIELD_OBJECT_PATH,
        interface=SHIELD_INTERFACE_NAME,
        member="VerdictApplied",
        body=[CONTAINER, _REQUEST_ID, action, ok],
    )


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
        assert remove_match.call_count == 3
        bus.remove_message_handler.assert_called_once()


# ── Signal dispatch ───────────────────────────────────────────────────


class TestShieldSignals:
    """ConnectionBlocked fires a notification; VerdictApplied updates it in place."""

    @pytest.mark.asyncio
    async def test_connection_blocked_creates_notification(self, mock_notifier: AsyncMock) -> None:
        bus = _mock_bus()
        sub = EventSubscriber(mock_notifier, bus=bus)
        sub._bus = bus
        sub._on_message(_connection_blocked_signal())
        await asyncio.sleep(0)
        mock_notifier.notify.assert_awaited_once()
        assert _REQUEST_ID in sub._pending
        assert sub._pending[_REQUEST_ID].dest == DEST_IP

    @pytest.mark.asyncio
    async def test_verdict_applied_updates_notification_in_place(
        self, mock_notifier: AsyncMock
    ) -> None:
        bus = _mock_bus()
        sub = EventSubscriber(mock_notifier, bus=bus)
        sub._bus = bus
        sub._on_message(_connection_blocked_signal())
        await asyncio.sleep(0)
        sub._on_message(_verdict_applied_signal(action="allow", ok=True))
        await asyncio.sleep(0)
        assert mock_notifier.notify.await_count == 2
        second_call = mock_notifier.notify.await_args_list[1]
        assert second_call.kwargs.get("replaces_id") == 42
        assert _REQUEST_ID not in sub._pending

    @pytest.mark.asyncio
    async def test_container_started_signal_is_logged_no_op(self, mock_notifier: AsyncMock) -> None:
        bus = _mock_bus()
        sub = EventSubscriber(mock_notifier, bus=bus)
        started = Message(
            message_type=MessageType.SIGNAL,
            sender=":1.77",
            path=SHIELD_OBJECT_PATH,
            interface=SHIELD_INTERFACE_NAME,
            member="ContainerStarted",
            body=[CONTAINER],
        )
        sub._on_message(started)
        await asyncio.sleep(0)
        mock_notifier.notify.assert_not_called()

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


# ── Verdict routing ───────────────────────────────────────────────────


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
        """ConnectionBlocked installs an on_action callback that routes to Verdict."""
        bus = _mock_bus()
        sub = EventSubscriber(mock_notifier, bus=bus)
        sub._bus = bus
        sub._on_message(_connection_blocked_signal())
        await asyncio.sleep(0)
        mock_notifier.on_action.assert_awaited_once()
        action_cb = mock_notifier.on_action.await_args[0][1]
        action_cb("allow")
        await asyncio.sleep(0)
        assert bus.call.await_count >= 1
        msg = bus.call.await_args[0][0]
        assert msg.member == "Verdict"
        assert msg.body == [CONTAINER, _REQUEST_ID, DEST_IP, "allow"]


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
