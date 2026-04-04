# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Story: send, receive, close.

With a running D-Bus session bus and notification daemon, the full
notification lifecycle — send, close, disconnect — must work end to
end without mocks.
"""

import pytest

from terok_dbus import DbusNotifier, Notifier, create_notifier

pytestmark = [pytest.mark.needs_dbus, pytest.mark.needs_notification_daemon]


class TestNotifyLifecycle:
    """Full notification lifecycle against a real session bus."""

    async def test_create_notifier_returns_dbus(self, dbus_session: str, notification_daemon: None):
        """Factory returns DbusNotifier when the bus is live."""
        notifier = await create_notifier()
        assert isinstance(notifier, DbusNotifier)
        await notifier.disconnect()

    async def test_notify_returns_positive_id(self, notifier: Notifier):
        """A sent notification gets a positive server-assigned ID."""
        nid = await notifier.notify("Integration test", "Hello from pytest")
        assert isinstance(nid, int)
        assert nid > 0

    async def test_close_does_not_raise(self, notifier: Notifier):
        """Closing an active notification succeeds silently."""
        nid = await notifier.notify("Close me")
        await notifier.close(nid)

    async def test_close_unknown_id_does_not_raise(self, notifier: Notifier):
        """Closing a non-existent ID is a no-op."""
        await notifier.close(999999)

    async def test_multiple_notifications(self, notifier: Notifier):
        """Multiple notifications get distinct IDs."""
        ids = set()
        for i in range(3):
            nid = await notifier.notify(f"Multi #{i}")
            assert nid > 0
            ids.add(nid)
        assert len(ids) == 3

    async def test_disconnect_is_idempotent(self, dbus_session: str, notification_daemon: None):
        """Calling disconnect() twice does not raise."""
        notifier = await create_notifier()
        assert isinstance(notifier, DbusNotifier)
        await notifier.disconnect()
        await notifier.disconnect()
