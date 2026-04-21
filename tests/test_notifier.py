# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for DbusNotifier — mocked dbus-fast interactions."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from terok_dbus._notifier import DbusNotifier


def _mock_bus() -> MagicMock:
    """Create a mock MessageBus with introspection and proxy wiring."""
    iface = MagicMock()
    iface.call_notify = AsyncMock(return_value=7)
    iface.call_close_notification = AsyncMock()

    proxy = MagicMock()
    proxy.get_interface.return_value = iface

    bus = MagicMock()
    bus.connect = AsyncMock(return_value=bus)
    bus.introspect = AsyncMock(return_value=MagicMock())
    bus.get_proxy_object.return_value = proxy
    bus.disconnect = MagicMock()

    return bus


@pytest.fixture
def mock_bus() -> MagicMock:
    """A pre-wired mock MessageBus."""
    return _mock_bus()


class TestDbusNotifierConnect:
    """Connection lifecycle tests."""

    async def test_lazy_connect_on_first_notify(self, mock_bus: MagicMock):
        with patch("terok_dbus._notifier.MessageBus", return_value=mock_bus):
            notifier = DbusNotifier("test-app")
            assert notifier._conn is None
            await notifier.notify("hello")
            assert notifier._conn is not None
            assert notifier._conn.bus is mock_bus

    async def test_connect_subscribes_to_signals(self, mock_bus: MagicMock):
        with patch("terok_dbus._notifier.MessageBus", return_value=mock_bus):
            notifier = DbusNotifier()
            await notifier.connect()
            iface = mock_bus.get_proxy_object.return_value.get_interface.return_value
            iface.on_action_invoked.assert_called_once_with(notifier._handle_action)
            iface.on_notification_closed.assert_called_once_with(notifier._handle_closed)

    async def test_disconnect_clears_state(self, mock_bus: MagicMock):
        with patch("terok_dbus._notifier.MessageBus", return_value=mock_bus):
            notifier = DbusNotifier()
            await notifier.connect()
            await notifier.disconnect()
            assert notifier._conn is None
            assert notifier._callbacks == {}

    async def test_disconnect_unsubscribes_signals(self, mock_bus: MagicMock):
        with patch("terok_dbus._notifier.MessageBus", return_value=mock_bus):
            notifier = DbusNotifier()
            await notifier.connect()
            iface = mock_bus.get_proxy_object.return_value.get_interface.return_value
            await notifier.disconnect()
            iface.off_action_invoked.assert_called_once_with(notifier._handle_action)
            iface.off_notification_closed.assert_called_once_with(notifier._handle_closed)

    async def test_connect_failure_disconnects_bus(self, mock_bus: MagicMock):
        mock_bus.introspect = AsyncMock(side_effect=RuntimeError("boom"))
        with patch("terok_dbus._notifier.MessageBus", return_value=mock_bus):
            notifier = DbusNotifier()
            with pytest.raises(RuntimeError, match="boom"):
                await notifier.connect()
            mock_bus.disconnect.assert_called_once()
            assert notifier._conn is None

    async def test_connect_and_notify_share_the_lock(self, mock_bus: MagicMock):
        """A ``connect()`` + ``notify()`` race must produce exactly one MessageBus."""
        with patch("terok_dbus._notifier.MessageBus", return_value=mock_bus) as cls:
            notifier = DbusNotifier()
            await asyncio.gather(notifier.connect(), notifier.notify("hi"))
        assert cls.call_count == 1
        mock_bus.connect.assert_awaited_once()


class TestDbusNotifierNotify:
    """Notification sending tests."""

    async def test_notify_passes_correct_args(self, mock_bus: MagicMock):
        with patch("terok_dbus._notifier.MessageBus", return_value=mock_bus):
            notifier = DbusNotifier("myapp")
            nid = await notifier.notify("Title", "Body", timeout_ms=5000)
            assert nid == 7
            iface = mock_bus.get_proxy_object.return_value.get_interface.return_value
            iface.call_notify.assert_awaited_once_with(
                "myapp",
                0,
                "",
                "Title",
                "Body",
                [],
                {},
                5000,
            )

    async def test_notify_passes_hints_replaces_id_app_icon(self, mock_bus: MagicMock):
        with patch("terok_dbus._notifier.MessageBus", return_value=mock_bus):
            notifier = DbusNotifier("myapp")
            hints = {"urgency": "mock_variant", "resident": "mock_bool"}
            await notifier.notify(
                "Title",
                replaces_id=42,
                app_icon="dialog-warning",
                hints=hints,
            )
            iface = mock_bus.get_proxy_object.return_value.get_interface.return_value
            call_args = iface.call_notify.call_args[0]
            assert call_args[1] == 42  # replaces_id
            assert call_args[2] == "dialog-warning"  # app_icon
            assert call_args[6] == {"urgency": "mock_variant", "resident": "mock_bool"}

    async def test_notify_flattens_actions(self, mock_bus: MagicMock):
        with patch("terok_dbus._notifier.MessageBus", return_value=mock_bus):
            notifier = DbusNotifier()
            await notifier.notify("t", actions=[("allow", "Allow"), ("deny", "Deny")])
            iface = mock_bus.get_proxy_object.return_value.get_interface.return_value
            call_args = iface.call_notify.call_args
            assert call_args[0][5] == ["allow", "Allow", "deny", "Deny"]

    async def test_second_notify_reuses_connection(self, mock_bus: MagicMock):
        with patch("terok_dbus._notifier.MessageBus", return_value=mock_bus):
            notifier = DbusNotifier()
            await notifier.notify("a")
            await notifier.notify("b")
            mock_bus.connect.assert_awaited_once()

    async def test_concurrent_notify_connects_once(self, mock_bus: MagicMock):
        with patch("terok_dbus._notifier.MessageBus", return_value=mock_bus):
            notifier = DbusNotifier()
            await asyncio.gather(notifier.notify("a"), notifier.notify("b"))
            mock_bus.connect.assert_awaited_once()


class TestDbusNotifierActions:
    """Action callback dispatch tests."""

    async def test_on_action_registers_callback(self, mock_bus: MagicMock):
        with patch("terok_dbus._notifier.MessageBus", return_value=mock_bus):
            notifier = DbusNotifier()
            cb = MagicMock()
            await notifier.on_action(7, cb)
            assert 7 in notifier._callbacks

    async def test_handle_action_dispatches(self, mock_bus: MagicMock):
        with patch("terok_dbus._notifier.MessageBus", return_value=mock_bus):
            notifier = DbusNotifier()
            cb = MagicMock()
            await notifier.on_action(7, cb)
            notifier._handle_action(7, "allow")
            cb.assert_called_once_with("allow")

    async def test_handle_action_ignores_unknown_id(self, mock_bus: MagicMock):
        with patch("terok_dbus._notifier.MessageBus", return_value=mock_bus):
            notifier = DbusNotifier()
            notifier._handle_action(999, "allow")  # should not raise

    async def test_handle_closed_removes_callback(self, mock_bus: MagicMock):
        with patch("terok_dbus._notifier.MessageBus", return_value=mock_bus):
            notifier = DbusNotifier()
            await notifier.on_action(7, MagicMock())
            notifier._handle_closed(7, 1)
            assert 7 not in notifier._callbacks

    async def test_close_removes_callback_and_calls_dbus(self, mock_bus: MagicMock):
        with patch("terok_dbus._notifier.MessageBus", return_value=mock_bus):
            notifier = DbusNotifier()
            await notifier.connect()
            await notifier.on_action(7, MagicMock())
            await notifier.close(7)
            assert 7 not in notifier._callbacks
            iface = mock_bus.get_proxy_object.return_value.get_interface.return_value
            iface.call_close_notification.assert_awaited_once_with(7)
