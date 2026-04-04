# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""PEP 544 protocol defining the Notifier interface."""

from collections.abc import Callable, Sequence
from typing import Protocol, runtime_checkable


@runtime_checkable
class Notifier(Protocol):
    """Structural type for desktop notification backends.

    Implementations must provide ``notify``, ``on_action``, ``close``, and
    ``disconnect``.  ``DbusNotifier`` talks to a real session bus;
    ``NullNotifier`` silently discards everything for headless environments.
    """

    async def notify(
        self,
        summary: str,
        body: str = "",
        *,
        actions: Sequence[tuple[str, str]] = (),
        timeout_ms: int = -1,
    ) -> int:
        """Send a desktop notification.

        Args:
            summary: Notification title.
            body: Optional body text.
            actions: ``(action_id, label)`` pairs rendered as buttons.
            timeout_ms: Expiration hint in milliseconds (``-1`` = server default).

        Returns:
            Server-assigned notification ID (``0`` for null implementations).
        """
        ...

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
        ...

    async def close(self, notification_id: int) -> None:
        """Close an active notification.

        Args:
            notification_id: ID returned by ``notify``.
        """
        ...

    async def disconnect(self) -> None:
        """Release backend resources (no-op for null backends)."""
        ...
