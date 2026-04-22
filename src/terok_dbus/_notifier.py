# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Desktop notifier backed by dbus-fast and the freedesktop Notifications spec."""

import asyncio
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dbus_fast.aio import MessageBus

from terok_dbus._constants import BUS_NAME, INTERFACE_NAME, OBJECT_PATH

# ``Path(__file__)`` can be relative under editable installs or alternative
# loaders; ``resolve()`` before ``as_uri()`` because the latter rejects
# relative paths with a ValueError that would fire at import time and
# prevent the module from loading at all.
_LOGO_PATH = Path(__file__).resolve().parent / "resources" / "terok-logo.png"

#: ``file://`` URI of the bundled terok logo.  Freedesktop daemons render a
#: PNG passed as ``app_icon`` alongside summary + body; this gives every
#: clearance notification a consistent brand mark without requiring the
#: operator to install a system icon theme.  Empty when the resource is
#: missing (editable installs that skipped package-data copy, tests running
#: against a checked-out source tree without the file) — callers fall
#: through to no icon.
_DEFAULT_APP_ICON = _LOGO_PATH.as_uri() if _LOGO_PATH.is_file() else ""


@dataclass(frozen=True)
class _Connection:
    """A live session-bus handle paired with its Notifications proxy interface."""

    bus: MessageBus
    interface: Any  # dbus_fast ProxyInterface — dynamic-attribute object


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
        self._conn: _Connection | None = None
        self._callbacks: dict[int, Callable[[str], None]] = {}
        self._connect_lock = asyncio.Lock()

    async def connect(self) -> None:
        """Idempotently open the session-bus connection and subscribe to signals.

        Safe to call concurrently and repeatedly: the lock serialises racing
        callers so exactly one MessageBus is ever created for this notifier.
        """
        if self._conn is not None:
            return
        async with self._connect_lock:
            if self._conn is not None:
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
            self._conn = _Connection(bus=bus, interface=iface)

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
        container_id: str = "",  # noqa: ARG002 — protocol kwarg ignored by desktop
        container_name: str = "",  # noqa: ARG002 — protocol kwarg ignored by desktop
        project: str = "",  # noqa: ARG002 — protocol kwarg ignored by desktop
        task_id: str = "",  # noqa: ARG002 — protocol kwarg ignored by desktop
        task_name: str = "",  # noqa: ARG002 — protocol kwarg ignored by desktop
    ) -> int:
        """Send a desktop notification.

        Freedesktop notifications render summary + body + actions only,
        so the structured identity kwargs (``container_id`` and the
        terok task triple) are dropped on the floor here — callers are
        expected to have folded the user-facing identity into ``body``
        already.  The kwargs stay in the signature for
        :class:`~terok_dbus._protocol.Notifier` conformance so callers
        don't have to branch on notifier kind.
        """
        await self.connect()
        assert self._conn is not None  # connect() post-condition

        actions_flat: list[str] = []
        for action_id, label in actions:
            actions_flat.extend((action_id, label))

        return await self._conn.interface.call_notify(
            self._app_name,
            replaces_id,
            app_icon or _DEFAULT_APP_ICON,
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
        if self._conn is not None:
            await self._conn.interface.call_close_notification(notification_id)

    async def disconnect(self) -> None:
        """Tear down the session-bus connection."""
        conn = self._conn
        if conn is None:
            return
        if hasattr(conn.interface, "off_action_invoked"):
            conn.interface.off_action_invoked(self._handle_action)
        if hasattr(conn.interface, "off_notification_closed"):
            conn.interface.off_notification_closed(self._handle_closed)
        conn.bus.disconnect()
        self._conn = None
        self._callbacks.clear()
