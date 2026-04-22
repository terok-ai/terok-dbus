# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Render clearance-hub events as desktop notifications.

Turns the event stream from :class:`ClearanceClient` into calls on an
injected :class:`Notifier`: a block arrives, the operator sees a popup
with Allow/Deny actions, clicks route back to the hub as a ``Verdict``.
Live-block dedup, shield-down popup tracking, and task-identity
resolution live here because they're all presentation concerns —
the hub stays transport-only.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from dbus_fast import Variant

from terok_dbus._client import ClearanceClient
from terok_dbus._identity import ContainerIdentity
from terok_dbus._wire import ClearanceEvent

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
# so the resolved state can overwrite it in place.

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
"""Verdict-ok / ShieldUp confirmations — normal + transient (brief, skip tray)."""

_HINT_LIFECYCLE: dict[str, Any] = {
    "urgency": Variant("y", 0),
    "transient": Variant("b", True),
}
"""ContainerStarted / ContainerExited — low + transient."""

_PROTO_NAMES: dict[int, str] = {6: "TCP", 17: "UDP"}


def _wallclock_hhmmss() -> str:
    """Return the current local time as ``HH:MM:SS`` for human-facing bodies."""
    from datetime import datetime

    return datetime.now().strftime("%H:%M:%S")  # noqa: DTZ005 — display-only


def _identity_label(identity: ContainerIdentity, fallback_id: str) -> str:
    """Compact identity string — task triple when known, else container name."""
    if identity.project and identity.task_id:
        core = f"{identity.project}/{identity.task_id}"
        return f"{core} · {identity.task_name}" if identity.task_name else core
    return identity.container_name or fallback_id


def _identity_line(identity: ContainerIdentity, fallback_id: str) -> str:
    """First line of a notification body — a prefixed :func:`_identity_label`."""
    prefix = "Task" if identity.project and identity.task_id else "Container"
    return f"{prefix}: {_identity_label(identity, fallback_id)}"


def _blocked_body(
    identity: ContainerIdentity,
    fallback_id: str,
    proto_name: str,
    count: int,
    first_seen: str,
) -> str:
    """Render the body for a ConnectionBlocked notification.

    For the first block the body is two lines; on every subsequent hit
    a third line carries the counter and the wall-clock time of the
    first block so the operator can see at a glance "how often, for how
    long" without opening an expanded view.
    """
    lines = [_identity_line(identity, fallback_id), f"Protocol: {proto_name}"]
    if count > 1:
        lines.append(f"Blocked {count} times since {first_seen}")
    return "\n".join(lines)


@dataclass
class _PendingBlock:
    """One outstanding blocked-connection event awaiting an operator verdict.

    ``identity`` is captured at block time and reused when
    ``verdict_applied`` lands — avoids a second resolver round-trip for
    the hot path of every operator click.
    """

    notification_id: int
    container: str
    request_id: str
    target: str
    """Domain if the reader cached one, else the destination IP.

    Serves as the verdict subject, the dedup key, and the resolved-title
    string — varlink's ``Verdict`` call carries it as ``dest`` (the hub
    dispatches to shield on shape: bare IP vs. dotted domain).
    """
    identity: ContainerIdentity = field(default_factory=ContainerIdentity)
    count: int = 1
    first_seen: str = ""


class EventSubscriber:
    """Bridge clearance-hub events into desktop notifications.

    Owns the presentation-layer state a rendering client needs: live-block
    dedup keyed on ``(container, target)``, the tracked ``ShieldDown``
    popup per container so ``ShieldUp`` can retire it, and verdict routing
    through notifier action callbacks.

    Args:
        notifier: Desktop notification backend (any ``Notifier`` works).
        client: Pre-configured :class:`ClearanceClient`.  When omitted,
            one is created on :meth:`start` pointing at *socket_path*
            (defaulting to :func:`default_clearance_socket_path`).
        identity_resolver: Turns a short container ID into a
            :class:`ContainerIdentity` so terok task annotations surface
            as "Task: project/task_id · name" bodies.  Called from a
            worker thread so a slow ``podman inspect`` doesn't stall
            the event loop.  ``None`` renders the raw container ID.
        socket_path: Clearance-socket override when *client* isn't
            supplied (tests).
    """

    def __init__(
        self,
        notifier: Notifier,
        client: ClearanceClient | None = None,
        *,
        identity_resolver: Callable[[str], ContainerIdentity] | None = None,
        socket_path: Path | None = None,
    ) -> None:
        """Initialise the subscriber with a notifier and transport."""
        self._notifier = notifier
        self._client = client or ClearanceClient(socket_path=socket_path)
        self._identity_resolver = identity_resolver
        # request_id → pending block + its notification.
        self._pending: dict[str, _PendingBlock] = {}
        # container → notification_id of the active ShieldDown popup, so
        # ShieldUp can close the matching one before firing its brief
        # confirmation.  A stale "Shield DOWN" popup after shield is back
        # is a security hazard, not a benign leftover.
        self._shield_down_notifs: dict[str, int] = {}
        # Background action / lifecycle tasks we spawn.
        self._tasks: set[asyncio.Task[None]] = set()

    # ── Lifecycle ─────────────────────────────────────────────────────

    async def start(self) -> None:
        """Connect to the clearance hub and begin rendering its event stream."""
        await self._client.start(self._on_event)
        _log.info("clearance subscriber online")

    async def stop(self) -> None:
        """Drain pending tasks and close the transport."""
        for task in self._tasks:
            task.cancel()
        await asyncio.sleep(0)
        self._tasks.clear()
        await self._client.stop()
        self._pending.clear()
        self._shield_down_notifs.clear()

    async def wait_closed(self) -> None:
        """Return when the underlying client's event stream has ended.

        Lets the notifier race ``wait_for_shutdown_signal`` against the
        hub going away, so ``systemctl restart terok-dbus`` triggers a
        clean notifier exit + systemd restart rather than leaving us
        silently subscribed to a dead socket.
        """
        await self._client.wait_closed()

    # ── Event dispatch ────────────────────────────────────────────────

    async def _on_event(self, event: ClearanceEvent) -> None:
        """Route one event to the right handler by its ``type`` discriminator."""
        if event.type == "connection_blocked":
            await self._handle_connection_blocked(event)
        elif event.type == "verdict_applied":
            await self._handle_verdict_applied(event)
        elif event.type == "container_started":
            _log.info("Container started: %s", event.container)
            self._dispatch(self._notify_container_started(event.container))
            self._dispatch_lifecycle("on_container_started", event.container)
        elif event.type == "container_exited":
            _log.info("Container exited: %s (reason=%s)", event.container, event.reason)
            self._dispatch(self._handle_container_exited(event.container))
            self._dispatch(self._notify_container_exited(event.container, event.reason))
            self._dispatch_lifecycle("on_container_exited", event.container, event.reason)
        elif event.type == "shield_up":
            _log.info("Shield up: %s", event.container)
            self._dispatch(self._notify_shield_up(event.container))
            self._dispatch_lifecycle("on_shield_up", event.container)
        elif event.type in {"shield_down", "shield_down_all"}:
            allow_all = event.type == "shield_down_all"
            _log.info("Shield down: %s (allow_all=%s)", event.container, allow_all)
            self._dispatch(self._handle_shield_down(event.container))
            self._dispatch(self._notify_shield_down(event.container, allow_all=allow_all))
            self._dispatch_lifecycle(
                "on_shield_down_all" if allow_all else "on_shield_down",
                event.container,
            )

    # ── connection_blocked / verdict_applied handlers ─────────────────

    async def _handle_connection_blocked(self, event: ClearanceEvent) -> None:
        """Prompt the operator to allow or deny a newly-blocked connection.

        A live prompt for the same ``(container, target)`` is reused
        instead of stacked — one decision, one target, one popup — and
        the verdict routes to the latest ``request_id`` because that's
        what the shield is blocking right now.
        """
        target = event.domain or event.dest
        if not target:
            _log.warning(
                "Dropping connection_blocked with empty dest and domain [%s]",
                event.request_id,
            )
            return
        proto_name = _PROTO_NAMES.get(event.proto, str(event.proto))
        identity = await self._resolve_identity(event.container)
        _log.info(
            "Blocked: %s:%d/%s (%s) [%s]",
            target,
            event.port,
            proto_name,
            event.container,
            event.request_id,
        )

        prior = self._live_block_on(event.container, target)
        count = prior.count + 1 if prior else 1
        first_seen = prior.first_seen if prior else _wallclock_hhmmss()

        nid = await self._notifier.notify(
            f"Blocked: {target}:{event.port}",
            _blocked_body(identity, event.container, proto_name, count, first_seen),
            actions=[("allow", "Allow"), ("deny", "Deny")],
            hints=_HINT_BLOCK_PENDING,
            timeout_ms=0,
            replaces_id=prior.notification_id if prior else 0,
            container_id=event.container,
            container_name=identity.container_name,
            project=identity.project,
            task_id=identity.task_id,
            task_name=identity.task_name,
        )
        # A raising notify() must leave the prior record intact so the
        # lifecycle handlers keep a handle on the orphan popup.
        if prior is not None:
            self._pending.pop(prior.request_id, None)
        self._pending[event.request_id] = _PendingBlock(
            notification_id=nid,
            container=event.container,
            request_id=event.request_id,
            target=target,
            identity=identity,
            count=count,
            first_seen=first_seen,
        )
        await self._notifier.on_action(
            nid,
            lambda action: self._dispatch(
                self._send_verdict(event.container, event.request_id, target, action)
            ),
        )

    def _live_block_on(self, container: str, target: str) -> _PendingBlock | None:
        """The pending block awaiting a verdict on this target, if any."""
        for pending in self._pending.values():
            if pending.container == container and pending.target == target:
                return pending
        return None

    async def _handle_verdict_applied(self, event: ClearanceEvent) -> None:
        """Replace the pending notification in place with the verdict outcome."""
        pending = self._pending.pop(event.request_id, None)
        if pending is None:
            return
        success_titles = {"allow": "Allowed", "deny": "Denied"}
        failure_titles = {"allow": "Allow failed", "deny": "Deny failed"}
        if event.ok:
            title = f"{success_titles.get(event.action, event.action.title())}: {pending.target}"
            hints = _HINT_CONFIRMATION
        else:
            title = (
                f"{failure_titles.get(event.action, event.action.title() + ' failed')}: "
                f"{pending.target}"
            )
            hints = _HINT_SECURITY_ALERT
        if event.container != pending.container:
            _log.warning(
                "verdict_applied container mismatch for %s: event=%s pending=%s",
                event.request_id,
                event.container,
                pending.container,
            )
        identity = pending.identity
        await self._notifier.notify(
            title,
            _identity_line(identity, pending.container),
            replaces_id=pending.notification_id,
            hints=hints,
            timeout_ms=-1,
            container_id=pending.container,
            container_name=identity.container_name,
            project=identity.project,
            task_id=identity.task_id,
            task_name=identity.task_name,
        )

    # ── shield_down / container_exited cleanup ────────────────────────

    async def _handle_shield_down(self, container: str) -> None:
        """Close pending block notifications for *container* — shield is off."""
        await self._purge_container(container)

    async def _handle_container_exited(self, container: str) -> None:
        """Clean pending blocks + any live ShieldDown popup when a container dies."""
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

    # ── shield state / lifecycle popups ───────────────────────────────

    async def _notify_shield_down(self, container: str, *, allow_all: bool) -> None:
        """Post a persistent security-alert notification for a manual shield drop."""
        identity = await self._resolve_identity(container)
        label = _identity_label(identity, container)
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
            container_name=identity.container_name,
            project=identity.project,
            task_id=identity.task_id,
            task_name=identity.task_name,
        )
        self._shield_down_notifs[container] = nid

    async def _notify_shield_up(self, container: str) -> None:
        """Close the stale ShieldDown popup (if any) and post a brief confirmation."""
        if (down_nid := self._shield_down_notifs.pop(container, None)) is not None:
            try:
                await self._notifier.close(down_nid)
            except Exception:
                _log.exception("Failed to close stale ShieldDown notification %d", down_nid)
        identity = await self._resolve_identity(container)
        label = _identity_label(identity, container)
        await self._notifier.notify(
            f"Shield up: {label}",
            "Outbound firewall restored.",
            hints=_HINT_CONFIRMATION,
            timeout_ms=-1,
            container_id=container,
            container_name=identity.container_name,
            project=identity.project,
            task_id=identity.task_id,
            task_name=identity.task_name,
        )

    async def _notify_container_started(self, container: str) -> None:
        """Low-urgency, transient confirmation that a shielded container came online."""
        identity = await self._resolve_identity(container)
        label = _identity_label(identity, container)
        await self._notifier.notify(
            f"Container started: {label}",
            "",
            hints=_HINT_LIFECYCLE,
            timeout_ms=-1,
            container_id=container,
            container_name=identity.container_name,
            project=identity.project,
            task_id=identity.task_id,
            task_name=identity.task_name,
        )

    async def _notify_container_exited(self, container: str, reason: str) -> None:
        """Low-urgency, transient confirmation that a shielded container stopped."""
        identity = await self._resolve_identity(container)
        label = _identity_label(identity, container)
        await self._notifier.notify(
            f"Container stopped: {label}",
            f"Reason: {reason}" if reason else "",
            hints=_HINT_LIFECYCLE,
            timeout_ms=-1,
            container_id=container,
            container_name=identity.container_name,
            project=identity.project,
            task_id=identity.task_id,
            task_name=identity.task_name,
        )

    # ── verdict routing ───────────────────────────────────────────────

    async def _send_verdict(
        self, container: str, request_id: str, target: str, action: str
    ) -> None:
        """Fire a verdict via the hub's varlink RPC channel."""
        _log.info("Sending verdict: %s / %s (%s) → %s", container, request_id, target, action)
        try:
            await self._client.verdict(container, request_id, target, action)
        except Exception:
            _log.exception("Failed to send verdict for %s", request_id)

    # ── Internal helpers ──────────────────────────────────────────────

    def _dispatch(self, coro: Coroutine[Any, Any, None]) -> None:
        """Schedule an async coroutine as a tracked background task."""
        task = asyncio.get_running_loop().create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _resolve_identity(self, container: str) -> ContainerIdentity:
        """Run the injected identity resolver on a worker thread — never block the loop.

        The default resolver shells out to ``podman inspect``; wrapping
        the sync call in :func:`asyncio.to_thread` keeps the first-miss
        case equally safe whether the resolver ships a cache or not.
        Any exception falls back to an empty identity so one bad
        container never knocks the notification pipeline off the rails.
        """
        if not container or self._identity_resolver is None:
            return ContainerIdentity()
        try:
            return await asyncio.to_thread(self._identity_resolver, container)
        except Exception:
            _log.exception("Identity resolution failed for %s", container)
            return ContainerIdentity()

    def _dispatch_lifecycle(self, method: str, *args: str) -> None:
        """Invoke a lifecycle hook on the notifier if it implements one.

        Notifiers that don't care (stock :class:`DbusNotifier`,
        :class:`NullNotifier`) don't expose the method; we no-op rather
        than error.  Consumers that do care (``CallbackNotifier`` for
        the TUI) get the event.
        """
        hook = getattr(self._notifier, method, None)
        if hook is None:
            return
        try:
            hook(*args)
        except Exception:
            _log.exception("Notifier %s raised for args=%s", method, args)
