# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Event subscriber bridging Shield1/Clearance1 D-Bus signals to desktop notifications.

Subscribes using **senderless match rules** so signals from any per-container
shield bridge (``org.terok.Shield1.Container_*``) are received.  Uses
``ListNames`` + ``NameOwnerChanged`` for instance discovery and sender
validation (MPRIS-style), and routes verdict method calls directly to the
originating bridge via its unique bus name.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Coroutine
from typing import TYPE_CHECKING, Any

from dbus_fast import MessageType, Variant
from dbus_fast.aio import MessageBus
from dbus_fast.message import Message

from terok_dbus._interfaces import (
    CLEARANCE_BUS_NAME,
    CLEARANCE_INTERFACE_NAME,
    CLEARANCE_OBJECT_PATH,
    SHIELD_BUS_NAME_PREFIX,
    SHIELD_INTERFACE_NAME,
    SHIELD_OBJECT_PATH,
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

# ── D-Bus daemon constants ────────────────────────────────────────────

_DBUS_DEST = "org.freedesktop.DBus"
_DBUS_PATH = "/org/freedesktop/DBus"
_DBUS_IFACE = "org.freedesktop.DBus"


async def _add_match(bus: MessageBus, rule: str) -> None:
    """Send an ``AddMatch`` call to the D-Bus daemon."""
    await bus.call(
        Message(
            destination=_DBUS_DEST,
            path=_DBUS_PATH,
            interface=_DBUS_IFACE,
            member="AddMatch",
            signature="s",
            body=[rule],
        )
    )


async def _remove_match(bus: MessageBus, rule: str) -> None:
    """Send a ``RemoveMatch`` call to the D-Bus daemon (best-effort)."""
    try:
        await bus.call(
            Message(
                destination=_DBUS_DEST,
                path=_DBUS_PATH,
                interface=_DBUS_IFACE,
                member="RemoveMatch",
                signature="s",
                body=[rule],
            )
        )
    except Exception:
        _log.debug("RemoveMatch failed for %r (bus may be disconnected)", rule)


async def _get_name_owner(bus: MessageBus, name: str) -> str | None:
    """Resolve a well-known bus name to its unique owner (e.g. ``:1.42``)."""
    try:
        reply = await bus.call(
            Message(
                destination=_DBUS_DEST,
                path=_DBUS_PATH,
                interface=_DBUS_IFACE,
                member="GetNameOwner",
                signature="s",
                body=[name],
            )
        )
        return reply.body[0] if reply.body else None
    except Exception:
        return None


class EventSubscriber:
    """Subscribe to Shield1 and Clearance1 D-Bus signals and present desktop notifications.

    Uses senderless match rules to receive signals from any per-container
    shield bridge (MPRIS-style ``org.terok.Shield1.Container_*`` bus names).
    Validates signal senders against a live registry built from ``ListNames``
    and ``NameOwnerChanged``.  Verdict method calls are routed directly to
    the bridge that emitted the original signal.

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
        self._pending: dict[int, str] = {}  # notification_id → request_id
        self._tasks: set[asyncio.Task[None]] = set()
        # Sender tracking: request_id → unique bus name of the originating bridge
        self._request_senders: dict[str, str] = {}
        # Instance registry: well-known name → unique bus name (for sender validation)
        self._known_shields: dict[str, str] = {}
        self._known_clearances: dict[str, str] = {}
        # Match rules for cleanup
        self._match_rules: list[str] = []

    # ── Lifecycle ─────────────────────────────────────────────────────

    async def start(self) -> None:
        """Connect to the session bus and subscribe to Shield1 and Clearance1 signals."""
        if self._bus is None:
            self._bus = await MessageBus().connect()

        # Discover existing bridge instances
        await self._discover_instances()

        # Subscribe to NameOwnerChanged — narrowed to terok bus names only
        # (arg0namespace matches any name starting with the prefix)
        shield_noc_rule = (
            f"type='signal',sender='{_DBUS_DEST}',path='{_DBUS_PATH}',"
            f"interface='{_DBUS_IFACE}',member='NameOwnerChanged',"
            f"arg0namespace='{SHIELD_BUS_NAME_PREFIX.rstrip('_')}'"
        )
        await _add_match(self._bus, shield_noc_rule)
        self._match_rules.append(shield_noc_rule)

        clearance_noc_rule = (
            f"type='signal',sender='{_DBUS_DEST}',path='{_DBUS_PATH}',"
            f"interface='{_DBUS_IFACE}',member='NameOwnerChanged',"
            f"arg0='{CLEARANCE_BUS_NAME}'"
        )
        await _add_match(self._bus, clearance_noc_rule)
        self._match_rules.append(clearance_noc_rule)

        # Senderless match rules for Shield1 signals
        shield_rule = (
            f"type='signal',interface='{SHIELD_INTERFACE_NAME}',path='{SHIELD_OBJECT_PATH}'"
        )
        await _add_match(self._bus, shield_rule)
        self._match_rules.append(shield_rule)

        # Senderless match rules for Clearance1 signals
        clearance_rule = (
            f"type='signal',interface='{CLEARANCE_INTERFACE_NAME}',path='{CLEARANCE_OBJECT_PATH}'"
        )
        await _add_match(self._bus, clearance_rule)
        self._match_rules.append(clearance_rule)

        # Register the unified message handler
        self._bus.add_message_handler(self._on_message)
        _log.info(
            "Subscribed to %s and %s (senderless, %d known shields)",
            SHIELD_INTERFACE_NAME,
            CLEARANCE_INTERFACE_NAME,
            len(self._known_shields),
        )

    async def stop(self) -> None:
        """Unsubscribe from signals and disconnect the bus if owned."""
        for task in self._tasks:
            task.cancel()
        await asyncio.sleep(0)
        self._tasks.clear()

        if self._bus is not None:
            self._bus.remove_message_handler(self._on_message)
            for rule in self._match_rules:
                await _remove_match(self._bus, rule)

        self._match_rules.clear()
        self._known_shields.clear()
        self._known_clearances.clear()
        self._request_senders.clear()
        self._pending.clear()

        if self._owns_bus and self._bus is not None:
            self._bus.disconnect()
            self._bus = None

    # ── Instance discovery ────────────────────────────────────────────

    async def _discover_instances(self) -> None:
        """Populate the known-bridges registry from currently owned bus names."""
        reply = await self._bus.call(
            Message(
                destination=_DBUS_DEST,
                path=_DBUS_PATH,
                interface=_DBUS_IFACE,
                member="ListNames",
                signature="",
                body=[],
            )
        )
        for name in reply.body[0]:
            if name.startswith(SHIELD_BUS_NAME_PREFIX):
                unique = await _get_name_owner(self._bus, name)
                if unique:
                    self._known_shields[name] = unique
                    _log.debug("Discovered shield bridge: %s → %s", name, unique)
            elif name == CLEARANCE_BUS_NAME:
                unique = await _get_name_owner(self._bus, name)
                if unique:
                    self._known_clearances[name] = unique

    def _on_name_owner_changed(self, name: str, old_owner: str, new_owner: str) -> None:
        """Track bridge appearance/disappearance via NameOwnerChanged."""
        if name.startswith(SHIELD_BUS_NAME_PREFIX):
            if new_owner:
                self._known_shields[name] = new_owner
                _log.info("Shield bridge appeared: %s → %s", name, new_owner)
            else:
                self._known_shields.pop(name, None)
                # Clean up pending verdicts for disappeared bridge
                stale = [
                    rid for rid, sender in self._request_senders.items() if sender == old_owner
                ]
                for rid in stale:
                    del self._request_senders[rid]
                _log.info("Shield bridge disappeared: %s (cleaned %d pending)", name, len(stale))
        elif name == CLEARANCE_BUS_NAME:
            if new_owner:
                self._known_clearances[name] = new_owner
            else:
                self._known_clearances.pop(name, None)
                stale = [
                    rid for rid, sender in self._request_senders.items() if sender == old_owner
                ]
                for rid in stale:
                    del self._request_senders[rid]
                _log.info(
                    "Clearance service disappeared: %s (cleaned %d pending)", name, len(stale)
                )

    def _is_known_sender(self, sender: str, interface: str) -> bool:
        """Check if a signal sender is from a known bridge instance."""
        if interface == SHIELD_INTERFACE_NAME:
            return sender in self._known_shields.values()
        if interface == CLEARANCE_INTERFACE_NAME:
            return sender in self._known_clearances.values()
        return False

    # ── Unified message handler ───────────────────────────────────────

    def _on_message(self, msg: Message) -> None:
        """Dispatch D-Bus messages to signal-specific handlers."""
        if msg.message_type != MessageType.SIGNAL:
            return

        # NameOwnerChanged from the daemon
        if (
            msg.interface == _DBUS_IFACE
            and msg.member == "NameOwnerChanged"
            and msg.sender == _DBUS_DEST
        ):
            body = msg.body
            if len(body) != 3 or not all(isinstance(part, str) for part in body):
                _log.warning("Ignoring malformed NameOwnerChanged body: %r", body)
                return
            self._on_name_owner_changed(body[0], body[1], body[2])
            return

        # Shield1 signals
        if msg.interface == SHIELD_INTERFACE_NAME and msg.path == SHIELD_OBJECT_PATH:
            if not self._is_known_sender(msg.sender, SHIELD_INTERFACE_NAME):
                _log.debug("Ignoring Shield1 signal from unknown sender %s", msg.sender)
                return
            if msg.member == "ConnectionBlocked" and len(msg.body) == 6:
                container, dest, port, proto, domain, request_id = msg.body
                self._request_senders[request_id] = msg.sender
                self._on_connection_blocked(container, dest, port, proto, domain, request_id)
            elif msg.member == "VerdictApplied" and len(msg.body) == 5:
                self._on_verdict_applied(*msg.body)
            return

        # Clearance1 signals
        if msg.interface == CLEARANCE_INTERFACE_NAME and msg.path == CLEARANCE_OBJECT_PATH:
            if not self._is_known_sender(msg.sender, CLEARANCE_INTERFACE_NAME):
                _log.debug("Ignoring Clearance1 signal from unknown sender %s", msg.sender)
                return
            if msg.member == "RequestReceived" and len(msg.body) == 6:
                self._request_senders[msg.body[0]] = msg.sender
                self._on_request_received(*msg.body)
            elif msg.member == "RequestResolved" and len(msg.body) == 3:
                self._on_request_resolved(*msg.body)

    # ── Signal handlers (sync → async dispatch) ───────────────────────

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

    # ── Async signal logic ────────────────────────────────────────────

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
        _log.info("Blocked: %s:%d/%s (%s) [%s]", display, port, proto_name, container, request_id)
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
        _log.info("Verdict: %s %s → %s (ok=%s)", container, dest, action, ok)
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
        self._request_senders.pop(request_id, None)

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
        _log.info("Clearance: %s/%s wants %s:%d [%s]", project, task, dest, port, request_id)
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
        _log.info("Resolved: %s → %s (ips=%s)", request_id, action, ips)
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
        self._request_senders.pop(request_id, None)

    # ── Method call helpers ───────────────────────────────────────────

    async def _send_verdict(self, request_id: str, action: str) -> None:
        """Send a Shield1.Verdict method call to the originating bridge."""
        sender = self._request_senders.get(request_id)
        if not sender:
            _log.warning("No known bridge for verdict on %s", request_id)
            return
        _log.info("Sending verdict: %s → %s (to %s)", request_id, action, sender)
        try:
            await self._bus.call(
                Message(
                    destination=sender,
                    path=SHIELD_OBJECT_PATH,
                    interface=SHIELD_INTERFACE_NAME,
                    member="Verdict",
                    signature="ss",
                    body=[request_id, action],
                )
            )
        except Exception:
            _log.exception("Failed to send verdict for %s", request_id)

    async def _send_resolve(self, request_id: str, action: str) -> None:
        """Send a Clearance1.Resolve method call to the originating service."""
        sender = self._request_senders.get(request_id)
        if not sender:
            _log.warning("No known service for resolve on %s", request_id)
            return
        _log.info("Sending resolve: %s → %s (to %s)", request_id, action, sender)
        try:
            await self._bus.call(
                Message(
                    destination=sender,
                    path=CLEARANCE_OBJECT_PATH,
                    interface=CLEARANCE_INTERFACE_NAME,
                    member="Resolve",
                    signature="ss",
                    body=[request_id, action],
                )
            )
        except Exception:
            _log.exception("Failed to send resolve for %s", request_id)

    # ── Internal helpers ──────────────────────────────────────────────

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
