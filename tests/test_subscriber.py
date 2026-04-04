# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for EventSubscriber — mocked bus and notifier interactions."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from terok_dbus._interfaces import (
    CLEARANCE_BUS_NAME,
    CLEARANCE_INTERFACE_NAME,
    SHIELD_BUS_NAME,
    SHIELD_INTERFACE_NAME,
)
from terok_dbus._subscriber import EventSubscriber
from tests.conftest import (
    CONTAINER,
    DEST_IP,
    DOMAIN,
    PROJECT,
    REASON,
    RESOLVED_IPS,
    TASK,
)


@pytest.fixture
def mock_notifier() -> AsyncMock:
    """A mock satisfying the Notifier protocol."""
    notifier = AsyncMock()
    notifier.notify = AsyncMock(return_value=42)
    notifier.on_action = AsyncMock()
    notifier.close = AsyncMock()
    notifier.disconnect = AsyncMock()
    return notifier


def _make_mock_bus() -> MagicMock:
    """Create a mock MessageBus with proxy objects for Shield1 and Clearance1."""
    shield_iface = MagicMock()
    shield_iface.call_verdict = AsyncMock(return_value=True)
    clearance_iface = MagicMock()
    clearance_iface.call_resolve = AsyncMock(return_value=True)

    shield_proxy = MagicMock()
    shield_proxy.get_interface.return_value = shield_iface
    clearance_proxy = MagicMock()
    clearance_proxy.get_interface.return_value = clearance_iface

    def get_proxy(name, _path, _node):
        return {SHIELD_BUS_NAME: shield_proxy, CLEARANCE_BUS_NAME: clearance_proxy}[name]

    bus = MagicMock()
    bus.get_proxy_object = MagicMock(side_effect=get_proxy)
    bus.disconnect = MagicMock()
    return bus


@pytest.fixture
def mock_bus() -> MagicMock:
    """A pre-wired mock bus."""
    return _make_mock_bus()


def _shield_iface(bus: MagicMock) -> MagicMock:
    """Extract the Shield1 interface mock from a bus mock."""
    return bus.get_proxy_object(SHIELD_BUS_NAME, None, None).get_interface(SHIELD_INTERFACE_NAME)


def _clearance_iface(bus: MagicMock) -> MagicMock:
    """Extract the Clearance1 interface mock from a bus mock."""
    return bus.get_proxy_object(CLEARANCE_BUS_NAME, None, None).get_interface(
        CLEARANCE_INTERFACE_NAME
    )


class TestEventSubscriberStart:
    """Subscription setup tests."""

    async def test_subscribes_to_shield_signals(
        self, mock_bus: MagicMock, mock_notifier: AsyncMock
    ):
        sub = EventSubscriber(mock_notifier, bus=mock_bus)
        await sub.start()
        iface = _shield_iface(mock_bus)
        iface.on_connection_blocked.assert_called_once()
        iface.on_verdict_applied.assert_called_once()
        await sub.stop()

    async def test_subscribes_to_clearance_signals(
        self, mock_bus: MagicMock, mock_notifier: AsyncMock
    ):
        sub = EventSubscriber(mock_notifier, bus=mock_bus)
        await sub.start()
        iface = _clearance_iface(mock_bus)
        iface.on_request_received.assert_called_once()
        iface.on_request_resolved.assert_called_once()
        await sub.stop()

    async def test_creates_bus_when_none_injected(self, mock_notifier: AsyncMock):
        bus = _make_mock_bus()
        bus.connect = AsyncMock(return_value=bus)
        with patch("terok_dbus._subscriber.MessageBus", return_value=bus):
            sub = EventSubscriber(mock_notifier)
            await sub.start()
            bus.connect.assert_awaited_once()
            await sub.stop()


class TestEventSubscriberShield:
    """Shield1 signal handling tests."""

    async def test_connection_blocked_creates_notification(
        self, mock_bus: MagicMock, mock_notifier: AsyncMock
    ):
        sub = EventSubscriber(mock_notifier, bus=mock_bus)
        await sub.start()

        iface = _shield_iface(mock_bus)
        callback = iface.on_connection_blocked.call_args[0][0]
        callback(CONTAINER, DEST_IP, 443, 6, DOMAIN, "req-1")
        await asyncio.sleep(0)

        mock_notifier.notify.assert_awaited_once()
        call_kwargs = mock_notifier.notify.call_args
        assert f"Blocked: {DOMAIN}:443" in call_kwargs[0][0]
        assert call_kwargs.kwargs["hints"] is not None
        assert ("accept", "Allow") in call_kwargs.kwargs["actions"]
        assert ("deny", "Deny") in call_kwargs.kwargs["actions"]
        await sub.stop()

    async def test_connection_blocked_uses_dest_when_no_domain(
        self, mock_bus: MagicMock, mock_notifier: AsyncMock
    ):
        sub = EventSubscriber(mock_notifier, bus=mock_bus)
        await sub.start()

        iface = _shield_iface(mock_bus)
        callback = iface.on_connection_blocked.call_args[0][0]
        callback(CONTAINER, DEST_IP, 80, 6, "", "req-2")
        await asyncio.sleep(0)

        summary = mock_notifier.notify.call_args[0][0]
        assert f"{DEST_IP}:80" in summary
        await sub.stop()

    async def test_connection_blocked_registers_action_callback(
        self, mock_bus: MagicMock, mock_notifier: AsyncMock
    ):
        sub = EventSubscriber(mock_notifier, bus=mock_bus)
        await sub.start()

        iface = _shield_iface(mock_bus)
        callback = iface.on_connection_blocked.call_args[0][0]
        callback(CONTAINER, DEST_IP, 443, 6, DOMAIN, "req-1")
        await asyncio.sleep(0)

        mock_notifier.on_action.assert_awaited_once()
        assert mock_notifier.on_action.call_args[0][0] == 42  # notification_id
        await sub.stop()

    async def test_action_calls_verdict(self, mock_bus: MagicMock, mock_notifier: AsyncMock):
        sub = EventSubscriber(mock_notifier, bus=mock_bus)
        await sub.start()

        iface = _shield_iface(mock_bus)
        callback = iface.on_connection_blocked.call_args[0][0]
        callback(CONTAINER, DEST_IP, 443, 6, DOMAIN, "req-1")
        await asyncio.sleep(0)

        # Extract the action callback passed to on_action and invoke it
        action_cb = mock_notifier.on_action.call_args[0][1]
        action_cb("accept")
        await asyncio.sleep(0)

        iface.call_verdict.assert_awaited_once_with("req-1", "accept")
        await sub.stop()

    async def test_verdict_applied_updates_notification(
        self, mock_bus: MagicMock, mock_notifier: AsyncMock
    ):
        sub = EventSubscriber(mock_notifier, bus=mock_bus)
        await sub.start()
        iface = _shield_iface(mock_bus)

        # First: ConnectionBlocked creates notification (id=42)
        blocked_cb = iface.on_connection_blocked.call_args[0][0]
        blocked_cb(CONTAINER, DEST_IP, 443, 6, DOMAIN, "req-1")
        await asyncio.sleep(0)

        # Second: VerdictApplied updates it
        mock_notifier.notify.reset_mock()
        verdict_cb = iface.on_verdict_applied.call_args[0][0]
        verdict_cb(CONTAINER, DEST_IP, "req-1", "accept", True)
        await asyncio.sleep(0)

        mock_notifier.notify.assert_awaited_once()
        assert mock_notifier.notify.call_args.kwargs["replaces_id"] == 42
        assert "Allowed" in mock_notifier.notify.call_args[0][0]
        await sub.stop()


class TestEventSubscriberClearance:
    """Clearance1 signal handling tests."""

    async def test_request_received_creates_notification(
        self, mock_bus: MagicMock, mock_notifier: AsyncMock
    ):
        sub = EventSubscriber(mock_notifier, bus=mock_bus)
        await sub.start()

        iface = _clearance_iface(mock_bus)
        callback = iface.on_request_received.call_args[0][0]
        callback("req-10", PROJECT, TASK, DOMAIN, 443, REASON)
        await asyncio.sleep(0)

        mock_notifier.notify.assert_awaited_once()
        summary = mock_notifier.notify.call_args[0][0]
        assert TASK in summary
        assert f"{DOMAIN}:443" in summary
        await sub.stop()

    async def test_action_calls_resolve(self, mock_bus: MagicMock, mock_notifier: AsyncMock):
        sub = EventSubscriber(mock_notifier, bus=mock_bus)
        await sub.start()

        iface = _clearance_iface(mock_bus)
        callback = iface.on_request_received.call_args[0][0]
        callback("req-10", PROJECT, TASK, DOMAIN, 443, REASON)
        await asyncio.sleep(0)

        action_cb = mock_notifier.on_action.call_args[0][1]
        action_cb("deny")
        await asyncio.sleep(0)

        iface.call_resolve.assert_awaited_once_with("req-10", "deny")
        await sub.stop()

    async def test_request_resolved_updates_notification(
        self, mock_bus: MagicMock, mock_notifier: AsyncMock
    ):
        sub = EventSubscriber(mock_notifier, bus=mock_bus)
        await sub.start()
        iface = _clearance_iface(mock_bus)

        received_cb = iface.on_request_received.call_args[0][0]
        received_cb("req-10", PROJECT, TASK, DOMAIN, 443, REASON)
        await asyncio.sleep(0)

        mock_notifier.notify.reset_mock()
        resolved_cb = iface.on_request_resolved.call_args[0][0]
        resolved_cb("req-10", "accept", RESOLVED_IPS)
        await asyncio.sleep(0)

        mock_notifier.notify.assert_awaited_once()
        assert mock_notifier.notify.call_args.kwargs["replaces_id"] == 42
        assert "Approved" in mock_notifier.notify.call_args[0][0]
        await sub.stop()


class TestEventSubscriberStop:
    """Teardown tests."""

    async def test_stop_unsubscribes_shield_signals(
        self, mock_bus: MagicMock, mock_notifier: AsyncMock
    ):
        sub = EventSubscriber(mock_notifier, bus=mock_bus)
        await sub.start()
        await sub.stop()
        iface = _shield_iface(mock_bus)
        iface.off_connection_blocked.assert_called_once()
        iface.off_verdict_applied.assert_called_once()

    async def test_stop_unsubscribes_clearance_signals(
        self, mock_bus: MagicMock, mock_notifier: AsyncMock
    ):
        sub = EventSubscriber(mock_notifier, bus=mock_bus)
        await sub.start()
        await sub.stop()
        iface = _clearance_iface(mock_bus)
        iface.off_request_received.assert_called_once()
        iface.off_request_resolved.assert_called_once()

    async def test_stop_disconnects_owned_bus(self, mock_notifier: AsyncMock):
        bus = _make_mock_bus()
        bus.connect = AsyncMock(return_value=bus)
        with patch("terok_dbus._subscriber.MessageBus", return_value=bus):
            sub = EventSubscriber(mock_notifier)
            await sub.start()
            await sub.stop()
            bus.disconnect.assert_called_once()

    async def test_stop_does_not_disconnect_injected_bus(
        self, mock_bus: MagicMock, mock_notifier: AsyncMock
    ):
        sub = EventSubscriber(mock_notifier, bus=mock_bus)
        await sub.start()
        await sub.stop()
        mock_bus.disconnect.assert_not_called()
