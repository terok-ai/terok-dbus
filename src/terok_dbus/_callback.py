# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Callback-driven notifier for programmatic consumers.

``CallbackNotifier`` is a headless ``Notifier`` backend that invokes
user-supplied callables instead of rendering UI.  It enables any
consumer — Textual TUI, web dashboard, CLI tool — to build its own
presentation on top of the ``EventSubscriber`` signal pipeline without
depending on a D-Bus desktop notification daemon.

Typical usage::

    notifier = CallbackNotifier(on_notify=my_handler)
    subscriber = EventSubscriber(notifier)
    await subscriber.start()
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any


@dataclass
class Notification:
    """Snapshot of a single notification posted by the subscriber.

    The identity fields (``container_id``, ``container_name``,
    ``project``, ``task_id``, ``task_name``) are presentation-layer
    context the subscriber's ``identity_resolver`` produced — empty
    strings when unresolved.  The desktop :class:`DbusNotifier`
    discards all of them; the TUI uses the task triple to render a
    Task column for terok-managed containers and falls back to the
    container name for standalone ones.
    """

    nid: int
    summary: str
    body: str
    actions: list[tuple[str, str]]
    replaces_id: int
    timeout_ms: int
    container_id: str = ""
    container_name: str = ""
    project: str = ""
    task_id: str = ""
    task_name: str = ""


class CallbackNotifier:
    """``Notifier`` backend that delegates rendering to caller-supplied hooks.

    Args:
        on_notify: Called for every ``notify()`` with a :class:`Notification`.
            Receives new notifications (``replaces_id == 0``) and in-place
            updates (``replaces_id > 0``, e.g. verdict results).
        on_container_started: Called for every ``ContainerStarted`` signal
            with the short container ID.  Optional — consumers that don't
            care about container lifecycle skip the parameter.
        on_container_exited: Called for every ``ContainerExited`` signal
            with ``(container, reason)``.  Optional, same semantics.
        on_shield_up: Called for every ``ShieldUp`` signal with the
            container identifier.  Lets the TUI flip a "shielded" badge
            on the per-container row without polling nft state.
        on_shield_down: Called for every ``ShieldDown`` signal — partial
            bypass (loopback-only traffic still allowed).
        on_shield_down_all: Called for every ``ShieldDownAll`` signal —
            unrestricted bypass.  Split from ``on_shield_down`` so the
            consumer can render the two modes differently.
    """

    def __init__(
        self,
        on_notify: Callable[[Notification], None] | None = None,
        *,
        on_container_started: Callable[[str], None] | None = None,
        on_container_exited: Callable[[str, str], None] | None = None,
        on_shield_up: Callable[[str], None] | None = None,
        on_shield_down: Callable[[str], None] | None = None,
        on_shield_down_all: Callable[[str], None] | None = None,
    ) -> None:
        """Bind optional notify and lifecycle callbacks."""
        self._on_notify = on_notify
        self._on_container_started = on_container_started
        self._on_container_exited = on_container_exited
        self._on_shield_up = on_shield_up
        self._on_shield_down = on_shield_down
        self._on_shield_down_all = on_shield_down_all
        self._next_id = 1
        self._callbacks: dict[int, Callable[[str], None]] = {}

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
        """Record the notification and invoke the ``on_notify`` hook.

        Returns a monotonically increasing ID, or *replaces_id* for updates.
        """
        nid = replaces_id if replaces_id else self._next_id
        if not replaces_id:
            self._next_id += 1
        notification = Notification(
            nid=nid,
            summary=summary,
            body=body,
            actions=list(actions),
            replaces_id=replaces_id,
            timeout_ms=timeout_ms,
            container_id=container_id,
            container_name=container_name,
            project=project,
            task_id=task_id,
            task_name=task_name,
        )
        if self._on_notify:
            self._on_notify(notification)
        return nid

    async def on_action(
        self,
        notification_id: int,
        callback: Callable[[str], None],
    ) -> None:
        """Store the action callback for later invocation."""
        self._callbacks[notification_id] = callback

    async def close(self, notification_id: int) -> None:
        """Remove the callback for a closed notification."""
        self._callbacks.pop(notification_id, None)

    async def disconnect(self) -> None:
        """Release all stored callbacks."""
        self._callbacks.clear()

    def invoke_action(self, notification_id: int, action_key: str) -> None:
        """Invoke the stored callback for a user verdict.

        This is the entry point for consumers that handle user input
        (Allow/Deny) and need to route the decision back through
        ``EventSubscriber`` to the D-Bus ``Verdict``/``Resolve`` method.
        """
        if cb := self._callbacks.pop(notification_id, None):
            cb(action_key)

    def on_container_started(self, container: str) -> None:
        """Forward a ``ContainerStarted`` lifecycle event to the consumer hook."""
        if self._on_container_started:
            self._on_container_started(container)

    def on_container_exited(self, container: str, reason: str) -> None:
        """Forward a ``ContainerExited`` lifecycle event to the consumer hook."""
        if self._on_container_exited:
            self._on_container_exited(container, reason)

    def on_shield_up(self, container: str) -> None:
        """Forward a ``ShieldUp`` signal to the consumer hook."""
        if self._on_shield_up:
            self._on_shield_up(container)

    def on_shield_down(self, container: str) -> None:
        """Forward a ``ShieldDown`` signal (partial bypass) to the consumer hook."""
        if self._on_shield_down:
            self._on_shield_down(container)

    def on_shield_down_all(self, container: str) -> None:
        """Forward a ``ShieldDownAll`` signal (full bypass) to the consumer hook."""
        if self._on_shield_down_all:
            self._on_shield_down_all(container)
