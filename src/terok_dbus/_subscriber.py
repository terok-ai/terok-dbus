# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Event subscriber that renders Shield1 / Clearance1 signals as desktop notifications.

Subscribes to a single unified interface — ``org.terok.Shield1`` — regardless
of sender: the hub owns the bus name, per-container emitters publish signals
ephemerally, and both produce the same ``ConnectionBlocked`` shape.  When
the operator clicks accept/deny, the subscriber sends ``Verdict`` to the hub;
when the hub returns ``VerdictApplied`` the notification updates in place.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Coroutine
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from dbus_fast import MessageType, Variant
from dbus_fast.aio import MessageBus
from dbus_fast.message import Message

from terok_dbus._interfaces import (
    CLEARANCE_BUS_NAME,
    CLEARANCE_INTERFACE_NAME,
    CLEARANCE_OBJECT_PATH,
    SHIELD_BUS_NAME,
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

_HINT_VERDICT_FAILED: dict[str, Any] = {
    "urgency": Variant("y", 2),
}
"""Hints for verdict-application failures: critical urgency so the operator
doesn't scroll past a 'nothing actually happened' notification with the
same styling as a successful apply."""

_PROTO_NAMES: dict[int, str] = {6: "TCP", 17: "UDP"}

# ── D-Bus daemon constants ────────────────────────────────────────────

_DBUS_DEST = "org.freedesktop.DBus"
_DBUS_PATH = "/org/freedesktop/DBus"
_DBUS_IFACE = "org.freedesktop.DBus"


@dataclass
class _PendingBlock:
    """One outstanding blocked-connection event awaiting an operator verdict."""

    notification_id: int
    container: str
    request_id: str
    dest: str


# ── Match-rule helpers ────────────────────────────────────────────────


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


class EventSubscriber:
    """Subscribe to Shield1 and Clearance1 signals and drive desktop notifications.

    Shield1 uses a single unified bus name; the subscriber listens on the
    interface (senderless) and routes verdicts back to the well-known hub
    name.  Clearance1 still follows the legacy per-sender routing and is
    left unchanged in this refactor.

    Args:
        notifier: Desktop notification backend.
        bus: Optional pre-connected ``MessageBus`` (for testing).  ``None``
            means we create and own a new session-bus connection on
            :meth:`start`.
    """

    def __init__(self, notifier: Notifier, bus: MessageBus | None = None) -> None:
        """Initialise the subscriber with a notifier and optional bus."""
        self._notifier = notifier
        self._bus = bus
        self._owns_bus = bus is None
        # request_id → pending block awaiting verdict + its notification.
        self._pending: dict[str, _PendingBlock] = {}
        # notification_id → request_id — used by the Clearance1 legacy path.
        self._clearance_pending: dict[int, str] = {}
        # For Clearance1: legacy per-sender routing (unchanged).
        self._clearance_senders: dict[str, str] = {}
        # Current unique name of whichever process owns ``org.terok.Shield1`` —
        # any same-session peer could otherwise spoof Shield1 signals onto our
        # state machine.  Tracked via NameOwnerChanged; seeded at startup.
        self._shield_owner: str | None = None
        # Match rules for cleanup
        self._match_rules: list[str] = []
        # Background verdict/resolve tasks
        self._tasks: set[asyncio.Task[None]] = set()

    # ── Lifecycle ─────────────────────────────────────────────────────

    async def start(self) -> None:
        """Connect to the session bus and subscribe to Shield1 + Clearance1 signals."""
        if self._bus is None:
            self._bus = await MessageBus().connect()

        # Shield1: interface-level match (the sender-filter happens at dispatch
        # time against ``_shield_owner`` so we can swap-in a restarted hub
        # without re-issuing the match rule).
        shield_rule = (
            f"type='signal',interface='{SHIELD_INTERFACE_NAME}',path='{SHIELD_OBJECT_PATH}'"
        )
        await _add_match(self._bus, shield_rule)
        self._match_rules.append(shield_rule)

        # Shield1: track owner via NameOwnerChanged so spoofed signals from
        # other session peers are rejected in ``_on_shield_signal``.
        shield_noc_rule = (
            f"type='signal',sender='{_DBUS_DEST}',path='{_DBUS_PATH}',"
            f"interface='{_DBUS_IFACE}',member='NameOwnerChanged',"
            f"arg0='{SHIELD_BUS_NAME}'"
        )
        await _add_match(self._bus, shield_noc_rule)
        self._match_rules.append(shield_noc_rule)

        # Clearance1: legacy senderless + NameOwnerChanged routing.
        clearance_rule = (
            f"type='signal',interface='{CLEARANCE_INTERFACE_NAME}',path='{CLEARANCE_OBJECT_PATH}'"
        )
        await _add_match(self._bus, clearance_rule)
        self._match_rules.append(clearance_rule)

        clearance_noc_rule = (
            f"type='signal',sender='{_DBUS_DEST}',path='{_DBUS_PATH}',"
            f"interface='{_DBUS_IFACE}',member='NameOwnerChanged',"
            f"arg0='{CLEARANCE_BUS_NAME}'"
        )
        await _add_match(self._bus, clearance_noc_rule)
        self._match_rules.append(clearance_noc_rule)

        self._bus.add_message_handler(self._on_message)
        # If the clearance or hub service is already running at startup,
        # NameOwnerChanged won't fire — seed the owner registries from the
        # bus's current name table.
        await self._seed_clearance_owner()
        await self._seed_shield_owner()
        _log.info("Subscribed to %s and %s", SHIELD_INTERFACE_NAME, CLEARANCE_INTERFACE_NAME)

    async def _seed_clearance_owner(self) -> None:
        """Populate the Clearance sender registry from the bus's current name table."""
        owner = await self._lookup_name_owner(CLEARANCE_BUS_NAME)
        if owner is not None:
            self._clearance_senders[CLEARANCE_BUS_NAME] = owner

    async def _seed_shield_owner(self) -> None:
        """Populate the hub-owner record from the bus's current name table."""
        self._shield_owner = await self._lookup_name_owner(SHIELD_BUS_NAME)

    async def _lookup_name_owner(self, bus_name: str) -> str | None:
        """Ask the bus for ``bus_name``'s current unique-name owner, or ``None``."""
        if self._bus is None:
            return None
        try:
            reply = await self._bus.call(
                Message(
                    destination=_DBUS_DEST,
                    path=_DBUS_PATH,
                    interface=_DBUS_IFACE,
                    member="GetNameOwner",
                    signature="s",
                    body=[bus_name],
                )
            )
        except Exception:
            return None  # Not owned yet — NameOwnerChanged will pick it up later.
        return reply.body[0] if reply.body else None

    async def stop(self) -> None:
        """Unsubscribe, disconnect the bus if owned, and cancel pending tasks."""
        for task in self._tasks:
            task.cancel()
        await asyncio.sleep(0)
        self._tasks.clear()

        if self._bus is not None:
            self._bus.remove_message_handler(self._on_message)
            for rule in self._match_rules:
                await _remove_match(self._bus, rule)

        self._match_rules.clear()
        self._pending.clear()
        self._clearance_pending.clear()
        self._clearance_senders.clear()
        self._shield_owner = None

        if self._owns_bus and self._bus is not None:
            self._bus.disconnect()
            self._bus = None

    # ── Unified message handler ───────────────────────────────────────

    def _on_message(self, msg: Message) -> None:
        """Dispatch D-Bus messages to signal-specific handlers."""
        if msg.message_type != MessageType.SIGNAL:
            return

        if (
            msg.interface == _DBUS_IFACE
            and msg.member == "NameOwnerChanged"
            and msg.sender == _DBUS_DEST
        ):
            body = msg.body
            if len(body) == 3 and all(isinstance(part, str) for part in body):
                self._on_name_owner_changed(body[0], body[1], body[2])
            return

        if msg.interface == SHIELD_INTERFACE_NAME and msg.path == SHIELD_OBJECT_PATH:
            self._on_shield_signal(msg)
            return

        if msg.interface == CLEARANCE_INTERFACE_NAME and msg.path == CLEARANCE_OBJECT_PATH:
            self._on_clearance_signal(msg)

    def _on_shield_signal(self, msg: Message) -> None:
        """Dispatch Shield1 signals by member name, rejecting spoofed senders.

        Fail closed: until we know who owns ``org.terok.Shield1``, every
        signal on that interface is refused.  Accepting signals with
        ``_shield_owner is None`` would let a same-session peer race the
        hub's startup and drive the subscriber's state machine before we
        ever learn whose messages to trust.
        """
        if self._shield_owner is None:
            _log.debug(
                "Dropping Shield1 signal from %s — hub owner not yet known",
                msg.sender,
            )
            return
        if msg.sender != self._shield_owner:
            _log.debug("Ignoring Shield1 signal from unknown sender %s", msg.sender)
            return
        if msg.member == "ConnectionBlocked" and len(msg.body) == 6:
            container, request_id, dest, port, proto, domain = msg.body
            self._dispatch(
                self._handle_connection_blocked(container, request_id, dest, port, proto, domain)
            )
        elif msg.member == "VerdictApplied" and len(msg.body) == 4:
            container, request_id, action, ok = msg.body
            self._dispatch(self._handle_verdict_applied(container, request_id, action, ok))
        elif msg.member == "ContainerStarted" and len(msg.body) == 1:
            _log.info("Container started: %s", msg.body[0])
        elif msg.member == "ContainerExited" and len(msg.body) == 2:
            _log.info("Container exited: %s (reason=%s)", msg.body[0], msg.body[1])

    def _on_clearance_signal(self, msg: Message) -> None:
        """Dispatch Clearance1 signals after validating the sender."""
        if msg.sender not in self._clearance_senders.values():
            _log.debug("Ignoring Clearance1 signal from unknown sender %s", msg.sender)
            return
        if msg.member == "RequestReceived" and len(msg.body) == 6:
            self._dispatch(self._handle_request_received(*msg.body))
        elif msg.member == "RequestResolved" and len(msg.body) == 3:
            self._dispatch(self._handle_request_resolved(*msg.body))

    def _on_name_owner_changed(self, name: str, _old_owner: str, new_owner: str) -> None:
        """Track the current owner of the two well-known bus names we care about."""
        if name == CLEARANCE_BUS_NAME:
            if new_owner:
                self._clearance_senders[name] = new_owner
            else:
                self._clearance_senders.pop(name, None)
        elif name == SHIELD_BUS_NAME:
            self._shield_owner = new_owner or None

    # ── Shield1 signal logic ──────────────────────────────────────────

    async def _handle_connection_blocked(
        self,
        container: str,
        request_id: str,
        dest: str,
        port: int,
        proto: int,
        domain: str,
    ) -> None:
        """Create a desktop notification for a blocked connection."""
        display = domain if domain else dest
        proto_name = _PROTO_NAMES.get(proto, str(proto))
        _log.info("Blocked: %s:%d/%s (%s) [%s]", display, port, proto_name, container, request_id)
        nid = await self._notifier.notify(
            f"Blocked: {display}:{port}",
            f"Container: {container}\nProtocol: {proto_name}",
            actions=[("allow", "Allow"), ("deny", "Deny")],
            hints=_HINT_CRITICAL,
            timeout_ms=0,
        )
        self._pending[request_id] = _PendingBlock(
            notification_id=nid, container=container, request_id=request_id, dest=dest
        )
        await self._notifier.on_action(
            nid,
            lambda action: self._dispatch(self._send_verdict(container, request_id, dest, action)),
        )

    async def _handle_verdict_applied(
        self, container: str, request_id: str, action: str, ok: bool
    ) -> None:
        """Replace the notification in place with the verdict outcome.

        On failure, change both the verb and the urgency: the old code said
        "Allowed: X (failed)" with normal-urgency styling, which reads as a
        success to everyone not pausing to parse the parenthetical — and
        showed up green in the clearance TUI.  Use "Allow failed" /
        "Deny failed" so the subject line reflects what actually happened,
        and bump the hint to critical so the desktop renders it as a warning.
        """
        pending = self._pending.pop(request_id, None)
        if pending is None:
            return
        success_titles = {"allow": "Allowed", "deny": "Denied"}
        failure_titles = {"allow": "Allow failed", "deny": "Deny failed"}
        if ok:
            title = f"{success_titles.get(action, action.title())}: {pending.dest}"
            hints = _HINT_RESOLVED
        else:
            title = f"{failure_titles.get(action, action.title() + ' failed')}: {pending.dest}"
            hints = _HINT_VERDICT_FAILED
        await self._notifier.notify(
            title,
            f"Container: {container}",
            replaces_id=pending.notification_id,
            hints=hints,
            timeout_ms=5000,
        )

    async def _send_verdict(self, container: str, request_id: str, dest: str, action: str) -> None:
        """Call ``Verdict`` on the hub (``org.terok.Shield1`` well-known name)."""
        _log.info("Sending verdict: %s / %s (%s) → %s", container, request_id, dest, action)
        try:
            await self._bus.call(
                Message(
                    destination=SHIELD_BUS_NAME,
                    path=SHIELD_OBJECT_PATH,
                    interface=SHIELD_INTERFACE_NAME,
                    member="Verdict",
                    signature="ssss",
                    body=[container, request_id, dest, action],
                )
            )
        except Exception:
            _log.exception("Failed to send verdict for %s", request_id)

    # ── Clearance1 signal logic (unchanged from prior design) ─────────

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
        self._clearance_pending[nid] = request_id
        await self._notifier.on_action(
            nid, lambda action_key: self._dispatch(self._send_resolve(request_id, action_key))
        )

    async def _handle_request_resolved(self, request_id: str, action: str, ips: list[str]) -> None:
        """Update the clearance notification in place with the resolution."""
        nid = self._nid_for_clearance_request(request_id)
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
        del self._clearance_pending[nid]

    async def _send_resolve(self, request_id: str, action: str) -> None:
        """Send a Clearance1.Resolve method call to the originating service."""
        sender = self._clearance_senders.get(CLEARANCE_BUS_NAME)
        if not sender:
            _log.warning("No known clearance service for resolve on %s", request_id)
            return
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

    def _nid_for_clearance_request(self, request_id: str) -> int | None:
        """Reverse lookup for the clearance notification id."""
        for nid, rid in self._clearance_pending.items():
            if rid == request_id:
                return nid
        return None
