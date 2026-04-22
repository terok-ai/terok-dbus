# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""PEP 544 protocol defining the Notifier interface."""

from collections.abc import Callable, Mapping, Sequence
from typing import Any, Protocol, runtime_checkable


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
        hints: Mapping[str, Any] | None = None,
        replaces_id: int = 0,
        app_icon: str = "",
        container_id: str = "",
        container_name: str = "",
        project: str = "",
        task_id: str = "",
        task_name: str = "",
    ) -> int:
        """Send a desktop notification.

        Args:
            summary: Notification title.
            body: Optional body text.
            actions: ``(action_id, label)`` pairs rendered as buttons.
            timeout_ms: Expiration hint in milliseconds (``-1`` = server default).
            hints: Freedesktop hint dict (values are ``dbus_fast.Variant`` for
                ``DbusNotifier``, ignored by ``NullNotifier``).
            replaces_id: Replace an existing notification in-place.
            app_icon: Icon name or ``file:///`` URI.
            container_id: Presentation-layer hint: the 12-char podman
                container ID the event refers to.  The desktop
                ``DbusNotifier`` ignores it; ``CallbackNotifier`` attaches
                it to the :class:`~terok_dbus._callback.Notification` so
                rich consumers can render it alongside the user-facing name.
            container_name: Podman ``--name`` matching the ID.  Same
                propagation rules as ``container_id``.
            project: Terok project slug when the container is orchestrator-
                managed (from the ``ai.terok.project`` annotation).  Empty
                for standalone containers.
            task_id: Terok task ID (``ai.terok.task`` annotation); empty
                for standalone containers.
            task_name: Human-readable task label from terok's metadata —
                mutable at any point in the task's life, so resolved live
                by callers, not snapshotted.  Empty when unknown.

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
