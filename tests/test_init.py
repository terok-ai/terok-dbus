# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the public API surface of terok_clearance."""

from unittest.mock import AsyncMock, MagicMock, patch

import terok_clearance
from terok_clearance import DbusNotifier, Notifier, NullNotifier, create_notifier


class TestPublicApi:
    """Verify that __all__ matches the actual public API."""

    def test_all_exports(self):
        expected = {
            "CLEARANCE_INTERFACE_NAME",
            "CallbackNotifier",
            "Clearance1Interface",
            "ClearanceClient",
            "ClearanceEvent",
            "ClearanceHub",
            "ContainerIdentity",
            "ContainerInfo",
            "ContainerInspector",
            "DbusNotifier",
            "EventSubscriber",
            "IdentityResolver",
            "InvalidAction",
            "Notification",
            "Notifier",
            "NullInspector",
            "NullNotifier",
            "ShieldCliFailed",
            "UnknownRequest",
            "VerdictTupleMismatch",
            "check_units_outdated",
            "configure_logging",
            "create_notifier",
            "default_clearance_socket_path",
            "install_notifier_service",
            "read_installed_unit_version",
            "serve",
            "uninstall_notifier_service",
            "uninstall_service",
            "wait_for_shutdown_signal",
        }
        assert set(terok_clearance.__all__) == expected

    def test_notifier_is_protocol(self):
        assert isinstance(NullNotifier(), Notifier)


class TestCreateNotifier:
    """Factory function tests."""

    async def test_returns_dbus_notifier_when_bus_available(self):
        mock_bus = MagicMock()
        mock_bus.connect = AsyncMock(return_value=mock_bus)
        mock_bus.introspect = AsyncMock(return_value=MagicMock())
        proxy = MagicMock()
        proxy.get_interface.return_value = MagicMock()
        mock_bus.get_proxy_object.return_value = proxy

        with patch("terok_clearance.notifications.desktop.MessageBus", return_value=mock_bus):
            notifier = await create_notifier("test")
            assert isinstance(notifier, DbusNotifier)

    async def test_returns_null_notifier_on_connection_failure(self):
        mock_bus = MagicMock()
        mock_bus.connect = AsyncMock(side_effect=OSError("no bus"))

        with patch("terok_clearance.notifications.desktop.MessageBus", return_value=mock_bus):
            notifier = await create_notifier()
            assert isinstance(notifier, NullNotifier)

    async def test_returns_null_notifier_on_invalid_address(self):
        with patch(
            "terok_clearance.notifications.desktop.MessageBus",
            side_effect=ValueError("could not open dbus info file"),
        ):
            notifier = await create_notifier()
            assert isinstance(notifier, NullNotifier)
