# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Desktop notifier backed by dbus-fast and the freedesktop Notifications spec."""

import asyncio
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from dbus_fast.aio import MessageBus

from terok_dbus._constants import BUS_NAME, INTERFACE_NAME, OBJECT_PATH


class DbusNotifier:
    """Send desktop notifications over the D-Bus session bus.

    The connection is established lazily on the first ``notify`` call.
    Action callbacks are dispatched from the ``ActionInvoked`` signal;
    stale callbacks are cleaned up automatically on ``NotificationClosed``.

    Args:
        app_name: Application name sent with every notification.
    """

    def __init__(self, app_name: str = "terok") -> None:
        """Initialise with the given application name."""
        self._app_name = app_name
        self._bus: MessageBus | None = None
        self._interface: object | None = None
        self._callbacks: dict[int, Callable[[str], None]] = {}
        self._connect_lock = asyncio.Lock()

    async def connect(self) -> None:
        """Idempotently open the session-bus connection and subscribe to signals.

        Safe to call concurrently and repeatedly: the lock serialises racing
        callers so exactly one MessageBus is ever created for this notifier.
        """
        if self._interface is not None:
            return
        async with self._connect_lock:
            if self._interface is not None:
                return
            bus = await MessageBus().connect()
            try:
                introspection = await bus.introspect(BUS_NAME, OBJECT_PATH)
                proxy = bus.get_proxy_object(BUS_NAME, OBJECT_PATH, introspection)
                iface = proxy.get_interface(INTERFACE_NAME)
                if hasattr(iface, "on_action_invoked"):
                    iface.on_action_invoked(self._handle_action)
                if hasattr(iface, "on_notification_closed"):
                    iface.on_notification_closed(self._handle_closed)
            except BaseException:
                # Catch ``BaseException`` so an ``asyncio.CancelledError``
                # (``BaseException`` subclass on 3.11+) mid-handshake doesn't
                # leak the already-connected bus.
                bus.disconnect()
                raise
            self._bus = bus
            self._interface = iface

    def _handle_action(self, notification_id: int, action_key: str) -> None:
        """Dispatch an ``ActionInvoked`` signal to the registered callback."""
        if callback := self._callbacks.get(notification_id):
            callback(action_key)

    def _handle_closed(self, notification_id: int, _reason: int) -> None:
        """Remove the callback for a closed notification."""
        self._callbacks.pop(notification_id, None)

    async def notify(
        self,
        summary: str,
        body: str = "",
        *,
        actions: Sequence[tuple[str, str]] = (),
        timeout_ms: int = -1,
        hints: Mapping[str, Any] | None = None,
        replaces_id: int = 0,
        app_icon: str = "",
    ) -> int:
        """Send a desktop notification.

        Args:
            summary: Notification title.
            body: Optional body text.
            actions: ``(action_id, label)`` pairs rendered as buttons.
            timeout_ms: Expiration hint in milliseconds (``-1`` = server default).
            hints: Freedesktop hint dict (values should be ``dbus_fast.Variant``).
            replaces_id: Replace an existing notification in-place.
            app_icon: Icon name or ``file:///`` URI.

        Returns:
            Server-assigned notification ID.
        """
        await self.connect()

        actions_flat: list[str] = []
        for action_id, label in actions:
            actions_flat.extend((action_id, label))

        return await self._interface.call_notify(  # type: ignore[union-attr]
            self._app_name,
            replaces_id,
            app_icon,
            summary,
            body,
            actions_flat,
            dict(hints) if hints is not None else {},
            timeout_ms,
        )

    async def on_action(
        self,
        notification_id: int,
        callback: Callable[[str], None],
    ) -> None:
        """Register a callback for when the user clicks an action button.

        Args:
            notification_id: ID returned by ``notify``.
            callback: Called with the ``action_id`` string when invoked.
        """
        self._callbacks[notification_id] = callback

    async def close(self, notification_id: int) -> None:
        """Close an active notification.

        Args:
            notification_id: ID returned by ``notify``.
        """
        self._callbacks.pop(notification_id, None)
        if self._interface is not None:
            await self._interface.call_close_notification(notification_id)  # type: ignore[union-attr]

    async def disconnect(self) -> None:
        """Tear down the session-bus connection."""
        if self._interface is None:
            return
        if hasattr(self._interface, "off_action_invoked"):
            self._interface.off_action_invoked(self._handle_action)
        if hasattr(self._interface, "off_notification_closed"):
            self._interface.off_notification_closed(self._handle_closed)
        self._bus.disconnect()  # type: ignore[union-attr]
        self._bus = None
        self._interface = None
        self._callbacks.clear()
