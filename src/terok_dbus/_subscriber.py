# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Event subscriber bridging Shield1/Clearance1 D-Bus signals to desktop notifications."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Coroutine
from typing import TYPE_CHECKING, Any

from dbus_fast import Variant
from dbus_fast.aio import MessageBus
from dbus_fast.introspection import Node

from terok_dbus._interfaces import (
    CLEARANCE_BUS_NAME,
    CLEARANCE_INTERFACE_NAME,
    CLEARANCE_OBJECT_PATH,
    CLEARANCE_XML,
    SHIELD_BUS_NAME,
    SHIELD_INTERFACE_NAME,
    SHIELD_OBJECT_PATH,
    SHIELD_XML,
)

if TYPE_CHECKING:
    from terok_dbus._protocol import Notifier

_log = logging.getLogger(__name__)

_HINT_CRITICAL: dict[str, Any] = {
    "urgency": Variant("y", 2),
    "resident": Variant("b", True),
}
"""Hints for pending-decision notifications: critical urgency, stay after action click."""

_HINT_RESOLVED: dict[str, Any] = {
    "urgency": Variant("y", 1),
}
"""Hints for resolved notifications: normal urgency."""

_PROTO_NAMES: dict[int, str] = {6: "TCP", 17: "UDP"}


class EventSubscriber:
    """Subscribe to Shield1 and Clearance1 D-Bus signals and present desktop notifications.

    Creates desktop notifications with Allow/Deny action buttons for blocked
    connections (Shield) and clearance requests (Clearance). Operator actions are
    routed back as ``Verdict`` / ``Resolve`` D-Bus method calls.

    Args:
        notifier: Desktop notification backend.
        bus: Optional pre-connected ``MessageBus`` (for testing). If ``None``,
            a new session-bus connection is created on ``start()``.
    """

    def __init__(self, notifier: Notifier, bus: MessageBus | None = None) -> None:
        """Initialise the subscriber with a notifier and optional bus."""
        self._notifier = notifier
        self._bus = bus
        self._owns_bus = bus is None
        self._shield_iface: Any | None = None
        self._clearance_iface: Any | None = None
        self._pending: dict[int, str] = {}  # notification_id → request_id
        self._tasks: set[asyncio.Task[None]] = set()

    async def start(self) -> None:
        """Connect to the session bus and subscribe to Shield1 and Clearance1 signals."""
        if self._bus is None:
            self._bus = await MessageBus().connect()

        shield_node = Node.parse(SHIELD_XML)
        shield_proxy = self._bus.get_proxy_object(SHIELD_BUS_NAME, SHIELD_OBJECT_PATH, shield_node)
        self._shield_iface = shield_proxy.get_interface(SHIELD_INTERFACE_NAME)
        self._shield_iface.on_connection_blocked(self._on_connection_blocked)
        self._shield_iface.on_verdict_applied(self._on_verdict_applied)

        clearance_node = Node.parse(CLEARANCE_XML)
        clearance_proxy = self._bus.get_proxy_object(
            CLEARANCE_BUS_NAME, CLEARANCE_OBJECT_PATH, clearance_node
        )
        self._clearance_iface = clearance_proxy.get_interface(CLEARANCE_INTERFACE_NAME)
        self._clearance_iface.on_request_received(self._on_request_received)
        self._clearance_iface.on_request_resolved(self._on_request_resolved)

    async def stop(self) -> None:
        """Unsubscribe from signals and disconnect the bus if owned."""
        for task in self._tasks:
            task.cancel()
        await asyncio.sleep(0)  # yield to let cancellations propagate
        self._tasks.clear()

        if self._shield_iface is not None:
            if hasattr(self._shield_iface, "off_connection_blocked"):
                self._shield_iface.off_connection_blocked(self._on_connection_blocked)
            if hasattr(self._shield_iface, "off_verdict_applied"):
                self._shield_iface.off_verdict_applied(self._on_verdict_applied)
        if self._clearance_iface is not None:
            if hasattr(self._clearance_iface, "off_request_received"):
                self._clearance_iface.off_request_received(self._on_request_received)
            if hasattr(self._clearance_iface, "off_request_resolved"):
                self._clearance_iface.off_request_resolved(self._on_request_resolved)

        if self._owns_bus and self._bus is not None:
            self._bus.disconnect()

        self._shield_iface = None
        self._clearance_iface = None
        self._pending.clear()

    # ── Signal handlers (sync → async dispatch) ────────────────────────

    def _on_connection_blocked(
        self,
        container: str,
        dest: str,
        port: int,
        proto: int,
        domain: str,
        request_id: str,
    ) -> None:
        """Handle a Shield1.ConnectionBlocked signal."""
        self._dispatch(
            self._handle_connection_blocked(container, dest, port, proto, domain, request_id)
        )

    def _on_verdict_applied(
        self, container: str, dest: str, request_id: str, action: str, ok: bool
    ) -> None:
        """Handle a Shield1.VerdictApplied signal."""
        self._dispatch(self._handle_verdict_applied(container, dest, request_id, action, ok))

    def _on_request_received(
        self,
        request_id: str,
        project: str,
        task: str,
        dest: str,
        port: int,
        reason: str,
    ) -> None:
        """Handle a Clearance1.RequestReceived signal."""
        self._dispatch(self._handle_request_received(request_id, project, task, dest, port, reason))

    def _on_request_resolved(self, request_id: str, action: str, ips: list[str]) -> None:
        """Handle a Clearance1.RequestResolved signal."""
        self._dispatch(self._handle_request_resolved(request_id, action, ips))

    # ── Async signal logic ─────────────────────────────────────────────

    async def _handle_connection_blocked(
        self,
        container: str,
        dest: str,
        port: int,
        proto: int,
        domain: str,
        request_id: str,
    ) -> None:
        """Create a notification for a blocked connection."""
        display = domain if domain else dest
        proto_name = _PROTO_NAMES.get(proto, str(proto))
        nid = await self._notifier.notify(
            f"Blocked: {display}:{port}",
            f"Container: {container}\nProtocol: {proto_name}",
            actions=[("accept", "Allow"), ("deny", "Deny")],
            hints=_HINT_CRITICAL,
            timeout_ms=0,
        )
        self._pending[nid] = request_id
        await self._notifier.on_action(
            nid, lambda action_key: self._dispatch(self._send_verdict(request_id, action_key))
        )

    async def _handle_verdict_applied(
        self, container: str, dest: str, request_id: str, action: str, ok: bool
    ) -> None:
        """Update the notification in-place with the verdict result."""
        nid = self._nid_for_request(request_id)
        if nid is None:
            return
        status = "Allowed" if action == "accept" else "Denied"
        suffix = "" if ok else " (failed)"
        await self._notifier.notify(
            f"{status}: {dest}{suffix}",
            f"Container: {container}",
            replaces_id=nid,
            hints=_HINT_RESOLVED,
            timeout_ms=5000,
        )
        del self._pending[nid]

    async def _handle_request_received(
        self,
        request_id: str,
        project: str,
        task: str,
        dest: str,
        port: int,
        reason: str,
    ) -> None:
        """Create a notification for a clearance request."""
        nid = await self._notifier.notify(
            f"Task {task} wants {dest}:{port}",
            f"Project: {project}\nReason: {reason}",
            actions=[("accept", "Allow"), ("deny", "Deny")],
            hints=_HINT_CRITICAL,
            timeout_ms=0,
        )
        self._pending[nid] = request_id
        await self._notifier.on_action(
            nid, lambda action_key: self._dispatch(self._send_resolve(request_id, action_key))
        )

    async def _handle_request_resolved(self, request_id: str, action: str, ips: list[str]) -> None:
        """Update the notification in-place with the resolution result."""
        nid = self._nid_for_request(request_id)
        if nid is None:
            return
        status = "Approved" if action == "accept" else "Denied"
        body = f"IPs: {', '.join(ips)}" if ips else ""
        await self._notifier.notify(
            f"{status}: {request_id}",
            body,
            replaces_id=nid,
            hints=_HINT_RESOLVED,
            timeout_ms=5000,
        )
        del self._pending[nid]

    # ── Method call helpers ────────────────────────────────────────────

    async def _send_verdict(self, request_id: str, action: str) -> None:
        """Send a Shield1.Verdict method call."""
        try:
            await self._shield_iface.call_verdict(request_id, action)
        except Exception:
            _log.exception("Failed to send verdict for %s", request_id)

    async def _send_resolve(self, request_id: str, action: str) -> None:
        """Send a Clearance1.Resolve method call."""
        try:
            await self._clearance_iface.call_resolve(request_id, action)
        except Exception:
            _log.exception("Failed to send resolve for %s", request_id)

    # ── Internal helpers ───────────────────────────────────────────────

    def _dispatch(self, coro: Coroutine[Any, Any, None]) -> None:
        """Schedule an async coroutine as a tracked background task."""
        task = asyncio.get_running_loop().create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _nid_for_request(self, request_id: str) -> int | None:
        """Find the notification ID for a request ID (reverse lookup)."""
        for nid, rid in self._pending.items():
            if rid == request_id:
                return nid
        return None
