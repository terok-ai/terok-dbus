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
from collections.abc import Callable, Coroutine
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

# ── Notification urgency buckets ──────────────────────────────────────
#
# We lean on server-default timeouts (``timeout_ms=-1``) wherever
# possible and let the urgency hint drive the lifecycle: GNOME never
# auto-expires ``urgency=2`` (critical), fires normal/low through short
# default timeouts, and respects the ``transient`` hint to keep
# low-value confirmations out of the message tray.  ``resident`` keeps
# an actionable notification visible after the user clicks Allow/Deny
# so VerdictApplied lands on something still on screen.

_HINT_BLOCK_PENDING: dict[str, Any] = {
    "urgency": Variant("y", 2),
    "resident": Variant("b", True),
}
"""Pending-decision (ConnectionBlocked) — critical + resident."""

_HINT_SECURITY_ALERT: dict[str, Any] = {
    "urgency": Variant("y", 2),
}
"""Shield-down / verdict-failed — critical, no resident."""

_HINT_CONFIRMATION: dict[str, Any] = {
    "urgency": Variant("y", 1),
    "transient": Variant("b", True),
}
"""Verdict-ok confirmations — normal + transient (brief, no tray clutter)."""

_HINT_LIFECYCLE: dict[str, Any] = {
    "urgency": Variant("y", 0),
    "transient": Variant("b", True),
}
"""ContainerStarted / ContainerExited / ShieldUp — low + transient."""

_PROTO_NAMES: dict[int, str] = {6: "TCP", 17: "UDP"}


def _wallclock_hhmmss() -> str:
    """Return the current local time as ``HH:MM:SS`` for human-facing bodies."""
    from datetime import datetime

    return datetime.now().strftime("%H:%M:%S")  # noqa: DTZ005 — display-only


def _blocked_body(container_label: str, proto_name: str, count: int, first_seen: str) -> str:
    """Render the body for a ConnectionBlocked notification.

    For the first block the body is two lines; on every subsequent hit
    a third line carries the counter and the wall-clock time of the
    first block so the operator can see at a glance "how often, for how
    long" without opening an expanded view.
    """
    lines = [f"Container: {container_label}", f"Protocol: {proto_name}"]
    if count > 1:
        lines.append(f"Blocked {count} times since {first_seen}")
    return "\n".join(lines)


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
    target: str
    """Domain if the reader cached one, else the destination IP.

    Serves as verdict subject, dedup key, and resolved-title string —
    see :meth:`EventSubscriber._handle_connection_blocked` for the
    dnsmasq rationale behind preferring the domain.
    """
    count: int = 1
    """How many times this target has been blocked since ``first_seen`` —
    rendered in the body as ``Blocked N times since HH:MM:SS`` so the
    operator can spot a tight loop at a glance.  Carried across re-blocks
    by :meth:`EventSubscriber._handle_connection_blocked`."""
    first_seen: str = ""
    """Wall-clock ``HH:MM:SS`` of the very first block on this key.  Empty
    until the first block happens (conceptually — the field is always set
    during normal dispatch).  Carried across re-blocks so the counter's
    denominator grows with something meaningful next to it."""


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
        name_resolver: Optional callable that maps a short container ID to
            a human-readable container name.  When provided, the subscriber
            uses the name in the notification body and passes both values
            to ``notify()`` so rich consumers (TUI) can render ``name (id)``.
            When ``None``, the ID is used in the body and ``container_name``
            is forwarded as empty.  The resolver is called on every
            ``ConnectionBlocked`` — callers that need caching should wrap
            it themselves (e.g. :class:`PodmanContainerNameResolver`).
    """

    def __init__(
        self,
        notifier: Notifier,
        bus: MessageBus | None = None,
        *,
        name_resolver: Callable[[str], str] | None = None,
    ) -> None:
        """Initialise the subscriber with a notifier and optional bus + resolver."""
        self._notifier = notifier
        self._bus = bus
        self._owns_bus = bus is None
        self._name_resolver = name_resolver
        # Dedup lookups scan the values — at a handful of live prompts the
        # extra index isn't worth the coherence burden.
        self._pending: dict[str, _PendingBlock] = {}
        # container → notification_id of the active ShieldDown popup, so
        # ShieldUp can close the matching one before firing its brief
        # confirmation.  A stale "Shield DOWN" popup after shield is back
        # is a security hazard, not a benign leftover.
        self._shield_down_notifs: dict[str, int] = {}
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
        self._shield_down_notifs.clear()
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
            (container,) = msg.body
            _log.info("Container started: %s", container)
            self._dispatch(self._notify_container_started(container))
            self._dispatch_lifecycle("on_container_started", container)
        elif msg.member == "ContainerExited" and len(msg.body) == 2:
            container, reason = msg.body
            _log.info("Container exited: %s (reason=%s)", container, reason)
            self._dispatch(self._handle_container_exited(container))
            self._dispatch(self._notify_container_exited(container, reason))
            self._dispatch_lifecycle("on_container_exited", container, reason)
        elif msg.member == "ShieldUp" and len(msg.body) == 1:
            (container,) = msg.body
            _log.info("Shield up: %s", container)
            self._dispatch(self._notify_shield_up(container))
            self._dispatch_lifecycle("on_shield_up", container)
        elif msg.member in {"ShieldDown", "ShieldDownAll"} and len(msg.body) == 1:
            (container,) = msg.body
            allow_all = msg.member == "ShieldDownAll"
            _log.info("Shield down: %s (allow_all=%s)", container, allow_all)
            self._dispatch(self._handle_shield_down(container))
            self._dispatch(self._notify_shield_down(container, allow_all=allow_all))
            self._dispatch_lifecycle(
                "on_shield_down_all" if allow_all else "on_shield_down", container
            )

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
        """Prompt the operator to allow or deny a newly-blocked connection.

        A live prompt for the same ``(container, target)`` is reused
        instead of stacked — one decision, one target, one popup — and
        the verdict routes to the latest ``request_id`` because that's
        what the shield is blocking right now.

        The target is the cached domain when the reader had one, else
        the destination IP.  Shield's ``allow`` dispatches on shape;
        only the domain form tracks future DNS rotations through
        dnsmasq's ipset integration.
        """
        target = domain or dest
        if not target:
            # Malformed signal: nothing to decide about and nothing shield
            # could act on (``allow_domain("")`` would poison dnsmasq config).
            _log.warning("Dropping ConnectionBlocked with empty dest and domain [%s]", request_id)
            return
        proto_name = _PROTO_NAMES.get(proto, str(proto))
        # Human-readable name in the body; raw ID still flows through
        # ``container_id`` for TUI consumers and verdict routing.
        name = await self._resolve_container_name(container)
        _log.info("Blocked: %s:%d/%s (%s) [%s]", target, port, proto_name, container, request_id)

        prior = self._live_block_on(container, target)
        count = prior.count + 1 if prior else 1
        first_seen = prior.first_seen if prior else _wallclock_hhmmss()

        nid = await self._notifier.notify(
            f"Blocked: {target}:{port}",
            _blocked_body(name or container, proto_name, count, first_seen),
            actions=[("allow", "Allow"), ("deny", "Deny")],
            hints=_HINT_BLOCK_PENDING,
            timeout_ms=0,
            replaces_id=prior.notification_id if prior else 0,
            container_id=container,
            container_name=name,
        )
        # A raising notify() must leave the prior record intact so the
        # lifecycle handlers keep a handle on the orphan popup.
        if prior is not None:
            self._pending.pop(prior.request_id, None)
        self._pending[request_id] = _PendingBlock(
            notification_id=nid,
            container=container,
            request_id=request_id,
            target=target,
            count=count,
            first_seen=first_seen,
        )
        await self._notifier.on_action(
            nid,
            lambda action: self._dispatch(
                self._send_verdict(container, request_id, target, action)
            ),
        )

    def _live_block_on(self, container: str, target: str) -> _PendingBlock | None:
        """The pending block awaiting a verdict on this target, if any."""
        for pending in self._pending.values():
            if pending.container == container and pending.target == target:
                return pending
        return None

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
            title = f"{success_titles.get(action, action.title())}: {pending.target}"
            hints = _HINT_CONFIRMATION
        else:
            title = f"{failure_titles.get(action, action.title() + ' failed')}: {pending.target}"
            hints = _HINT_SECURITY_ALERT
        # ``pending.container`` is the ground truth for this notification
        # thread — captured when ConnectionBlocked landed.  Treat the
        # signal's own ``container`` as advisory: it should match, but if
        # the hub ever miswires one we'd rather log the drift than render
        # one notification with two different container labels.
        if container != pending.container:
            _log.warning(
                "VerdictApplied container mismatch for %s: signal=%s pending=%s",
                request_id,
                container,
                pending.container,
            )
        name = await self._resolve_container_name(pending.container)
        await self._notifier.notify(
            title,
            f"Container: {name or pending.container}",
            replaces_id=pending.notification_id,
            hints=hints,
            timeout_ms=-1,
            container_id=pending.container,
            container_name=name,
        )

    async def _handle_shield_down(self, container: str) -> None:
        """Close pending block notifications for *container* — shield is off.

        While shield is in bypass, any block we previously asked the operator
        to clear is stale: traffic is flowing already, so clicking Allow/Deny
        would write into an allowlist nobody is consulting right now.
        ``ShieldUp`` doesn't need a companion — when shield comes back the
        next block triggers a fresh ``ConnectionBlocked`` and the flow
        starts over.
        """
        await self._purge_container(container)

    async def _handle_container_exited(self, container: str) -> None:
        """Close pending block notifications when *container* dies without ShieldDown.

        Clean-stop paths usually emit ``ShieldDown`` first, but a kill or
        OOM leaves ``ContainerExited`` as the only signal — without a
        purge the pending records and on-screen popups would leak until
        the subscriber restarts.  Idempotent alongside ``_handle_shield_down``.

        Also dismisses any tracked ``ShieldDown`` popup for this container:
        the container is gone, so a persistent "Shield down: X" notification
        is misleading on screen and the stale ``notification_id`` would
        otherwise be reused by ``replaces_id`` on a future container with
        the same label.  This lives here rather than in ``_purge_container``
        because ``_handle_shield_down`` also funnels through the purge,
        concurrently with ``_notify_shield_down`` — closing the popup there
        would race the one we're about to post.
        """
        await self._purge_container(container)
        if (down_nid := self._shield_down_notifs.pop(container, None)) is not None:
            try:
                await self._notifier.close(down_nid)
            except Exception:
                _log.exception(
                    "Failed to close stale ShieldDown notification %d for %s",
                    down_nid,
                    container,
                )

    async def _purge_container(self, container: str) -> None:
        """Drop every pending block for *container* and close its popups."""
        stale = [pending for pending in self._pending.values() if pending.container == container]
        for pending in stale:
            self._pending.pop(pending.request_id, None)
            try:
                await self._notifier.close(pending.notification_id)
            except Exception:
                _log.exception(
                    "Failed to close stale notification %d for %s",
                    pending.notification_id,
                    container,
                )

    async def _notify_shield_down(self, container: str, *, allow_all: bool) -> None:
        """Post a persistent security-alert notification for a manual shield drop.

        Critical urgency (GNOME doesn't auto-expire those), no ``resident``
        — the operator just needs to see that shield is off.  Subsequent
        drops for the same container reuse the tracked ``notification_id``
        via ``replaces_id`` so we don't pile up stale popups if shield
        flips a few times in a row.
        """
        name = await self._resolve_container_name(container)
        label = name or container
        if allow_all:
            title = f"Shield full bypass: {label}"
            body = "Outbound firewall fully disabled — every destination is reachable."
        else:
            title = f"Shield down: {label}"
            body = "Outbound firewall bypassed — allowlist is not enforced."
        replaces_id = self._shield_down_notifs.get(container, 0)
        nid = await self._notifier.notify(
            title,
            body,
            hints=_HINT_SECURITY_ALERT,
            timeout_ms=-1,
            replaces_id=replaces_id,
            container_id=container,
            container_name=name,
        )
        self._shield_down_notifs[container] = nid

    async def _notify_shield_up(self, container: str) -> None:
        """Close the stale ShieldDown popup (if any) and post a brief confirmation.

        A ``ShieldDown`` notification is an active-state warning; once
        shield is back it becomes misinformation.  Close the old popup
        by its tracked ``notification_id`` before firing the brief
        ``ShieldUp`` confirmation so the operator never sees both on
        screen together.
        """
        if (down_nid := self._shield_down_notifs.pop(container, None)) is not None:
            try:
                await self._notifier.close(down_nid)
            except Exception:
                _log.exception("Failed to close stale ShieldDown notification %d", down_nid)
        name = await self._resolve_container_name(container)
        label = name or container
        await self._notifier.notify(
            f"Shield up: {label}",
            "Outbound firewall restored.",
            hints=_HINT_LIFECYCLE,
            timeout_ms=-1,
            container_id=container,
            container_name=name,
        )

    async def _notify_container_started(self, container: str) -> None:
        """Low-urgency, transient confirmation that a shielded container came online."""
        name = await self._resolve_container_name(container)
        label = name or container
        await self._notifier.notify(
            f"Container started: {label}",
            "",
            hints=_HINT_LIFECYCLE,
            timeout_ms=-1,
            container_id=container,
            container_name=name,
        )

    async def _notify_container_exited(self, container: str, reason: str) -> None:
        """Low-urgency, transient confirmation that a shielded container stopped."""
        name = await self._resolve_container_name(container)
        label = name or container
        await self._notifier.notify(
            f"Container stopped: {label}",
            f"Reason: {reason}" if reason else "",
            hints=_HINT_LIFECYCLE,
            timeout_ms=-1,
            container_id=container,
            container_name=name,
        )

    async def _send_verdict(
        self, container: str, request_id: str, target: str, action: str
    ) -> None:
        """Route the operator's verdict to the hub's ``Shield1.Verdict`` method."""
        _log.info("Sending verdict: %s / %s (%s) → %s", container, request_id, target, action)
        try:
            await self._bus.call(
                Message(
                    destination=SHIELD_BUS_NAME,
                    path=SHIELD_OBJECT_PATH,
                    interface=SHIELD_INTERFACE_NAME,
                    member="Verdict",
                    signature="ssss",
                    body=[container, request_id, target, action],
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
            hints=_HINT_BLOCK_PENDING,
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
            hints=_HINT_CONFIRMATION,
            timeout_ms=-1,
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

    async def _resolve_container_name(self, container: str) -> str:
        """Run the injected resolver on a worker thread — never block the loop.

        The default :class:`PodmanContainerNameResolver` shells out to
        ``podman inspect`` with a 5 s timeout; the first-time miss for each
        container would otherwise stall every other coroutine on the hub
        (incoming signals, outgoing Notify calls, shutdown handlers).
        Subsequent calls are cache hits, but wrapping the sync call in
        :func:`asyncio.to_thread` makes the first-miss case equally safe
        and keeps the two code paths symmetric.  Any exception (malformed
        argv, unexpected podman behaviour) falls back to ``""`` so one bad
        container never knocks the notification pipeline off the rails.
        """
        if not container or self._name_resolver is None:
            return ""
        try:
            return await asyncio.to_thread(self._name_resolver, container)
        except Exception:
            _log.exception("Container name resolution failed for %s", container)
            return ""

    def _dispatch_lifecycle(self, method: str, *args: str) -> None:
        """Invoke a lifecycle hook on the notifier if it implements one.

        Notifiers that don't care about container lifecycle (the stock
        desktop :class:`DbusNotifier`, :class:`NullNotifier`) simply don't
        expose the method; we no-op rather than error.  Consumers that do
        care (``CallbackNotifier`` for the TUI) get the event.
        """
        hook = getattr(self._notifier, method, None)
        if hook is None:
            return
        try:
            hook(*args)
        except Exception:
            _log.exception("Notifier %s raised for args=%s", method, args)

    def _nid_for_clearance_request(self, request_id: str) -> int | None:
        """Reverse lookup for the clearance notification id."""
        for nid, rid in self._clearance_pending.items():
            if rid == request_id:
                return nid
        return None
