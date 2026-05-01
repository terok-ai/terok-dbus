# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Render clearance-hub events as desktop notifications.

Turns the event stream from [`ClearanceClient`][terok_clearance.ClearanceClient] into calls on an
injected [`Notifier`][terok_clearance.client.subscriber.Notifier]: a block arrives, the operator sees a popup
with Allow/Deny actions, clicks route back to the hub as a ``Verdict``.
Live-block dedup and shield-down popup tracking live here because
they're presentation concerns; identity resolution does not — the
shield reader resolves the orchestrator-supplied dossier at emit time
and ships it on every event, so the renderer just reads it.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Coroutine
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from dbus_fast import Variant

from terok_clearance.client.client import ClearanceClient
from terok_clearance.domain.events import ClearanceEvent

if TYPE_CHECKING:
    from terok_clearance.notifications.protocol import Notifier

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


def _identity_label(dossier: dict[str, str], fallback_id: str) -> str:
    """Compact identity string — task triple when known, else container name.

    Keys consumed from the dossier:

    * ``project`` + ``task`` — present together promotes the popup to the
      task-aware shape ``project/task[ · name]``.
    * ``name`` — the human-readable label (task name or container name,
      depending on what the orchestrator publishes).  Used as the suffix
      after the task triple, or as the standalone label when no task is
      bound.
    """
    project = dossier.get("project", "")
    task = dossier.get("task", "")
    name = dossier.get("name", "")
    if project and task:
        core = f"{project}/{task}"
        return f"{core} · {name}" if name else core
    return name or fallback_id


def _identity_line(dossier: dict[str, str], fallback_id: str) -> str:
    """First line of a notification body — a prefixed `_identity_label`."""
    prefix = "Task" if dossier.get("project") and dossier.get("task") else "Container"
    return f"{prefix}: {_identity_label(dossier, fallback_id)}"


def _blocked_body(
    dossier: dict[str, str],
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
    lines = [_identity_line(dossier, fallback_id), f"Protocol: {proto_name}"]
    if count > 1:
        lines.append(f"Blocked {count} times since {first_seen}")
    return "\n".join(lines)


def _notify_kwargs(dossier: dict[str, str]) -> dict[str, str]:
    """Map the dossier dict to the notifier's typed kwargs.

    The notifier API still wants per-key arguments (``container_name``,
    ``project``, ``task_id``, ``task_name``) so action-router code paths
    that key on identity stay typed.  This is the one place the new
    flat dossier translates back to that legacy shape; one helper, one
    seam.
    """
    return {
        "container_name": dossier.get("container_name", "") or dossier.get("name", ""),
        "project": dossier.get("project", ""),
        "task_id": dossier.get("task", ""),
        "task_name": dossier.get("name", ""),
    }


@dataclass
class _PendingBlock:
    """One outstanding blocked-connection event awaiting an operator verdict.

    ``dossier`` is captured at block time and reused when
    ``verdict_applied`` lands so the resolved popup carries the same
    identity the operator just clicked on, regardless of whether the
    hub has since received a renamed-task event for the same container.
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
    dossier: dict[str, str] = field(default_factory=dict)
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
        client: Pre-configured [`ClearanceClient`][terok_clearance.ClearanceClient].  When omitted,
            one is created on [`start`][terok_clearance.client.subscriber.EventSubscriber.start] pointing at *socket_path*
            (defaulting to [`default_clearance_socket_path`][terok_clearance.default_clearance_socket_path]).
        socket_path: Clearance-socket override when *client* isn't
            supplied (tests).
    """

    def __init__(
        self,
        notifier: Notifier,
        client: ClearanceClient | None = None,
        *,
        socket_path: Path | None = None,
    ) -> None:
        """Initialise the subscriber with a notifier and transport."""
        self._notifier = notifier
        self._client = client or ClearanceClient(socket_path=socket_path)
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
        """Drain pending tasks and close the transport.

        Closes the client first so no new handler tasks are scheduled,
        then awaits the currently-tracked tasks to settle (with their
        own ``CancelledError`` suppressed).  A bare ``sleep(0)`` would
        yield only one loop turn — not enough for cancellation to
        propagate through chained awaits — and ``tasks.clear()`` on its
        own would drop references to tasks still writing to handles we
        then close.
        """
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._tasks.clear()
        await self._client.stop()
        self._pending.clear()
        self._shield_down_notifs.clear()

    def poke_reconnect(self) -> None:
        """Cut short any in-flight reconnect back-off — forwards to the client."""
        self._client.poke_reconnect()

    # ── Event dispatch ────────────────────────────────────────────────

    async def _on_event(self, event: ClearanceEvent) -> None:
        """Route one event to the right handler by its ``type`` discriminator."""
        if event.type == "connection_blocked":
            await self._handle_connection_blocked(event)
        elif event.type == "verdict_applied":
            await self._handle_verdict_applied(event)
        elif event.type == "container_started":
            _log.info("Container started: %s", event.container)
            self._dispatch(self._notify_container_started(event.container, event.dossier))
            self._dispatch_lifecycle("on_container_started", event.container)
        elif event.type == "container_exited":
            _log.info("Container exited: %s (reason=%s)", event.container, event.reason)
            self._dispatch(self._handle_container_exited(event.container))
            self._dispatch(
                self._notify_container_exited(event.container, event.reason, event.dossier)
            )
            self._dispatch_lifecycle("on_container_exited", event.container, event.reason)
        elif event.type == "shield_up":
            _log.info("Shield up: %s", event.container)
            self._dispatch(self._notify_shield_up(event.container, event.dossier))
            self._dispatch_lifecycle("on_shield_up", event.container)
        elif event.type in {"shield_down", "shield_down_all"}:
            allow_all = event.type == "shield_down_all"
            _log.info("Shield down: %s (allow_all=%s)", event.container, allow_all)
            self._dispatch(self._handle_shield_down(event.container))
            self._dispatch(
                self._notify_shield_down(event.container, event.dossier, allow_all=allow_all)
            )
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
        dossier = event.dossier
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
            _blocked_body(dossier, event.container, proto_name, count, first_seen),
            actions=[("allow", "Allow"), ("deny", "Deny")],
            hints=_HINT_BLOCK_PENDING,
            timeout_ms=0,
            replaces_id=prior.notification_id if prior else 0,
            container_id=event.container,
            **_notify_kwargs(dossier),
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
            dossier=dossier,
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
        dossier = pending.dossier
        await self._notifier.notify(
            title,
            _identity_line(dossier, pending.container),
            replaces_id=pending.notification_id,
            hints=hints,
            timeout_ms=-1,
            container_id=pending.container,
            **_notify_kwargs(dossier),
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

    async def _notify_shield_down(
        self, container: str, dossier: dict[str, str], *, allow_all: bool
    ) -> None:
        """Post a persistent security-alert notification for a manual shield drop."""
        label = _identity_label(dossier, container)
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
            **_notify_kwargs(dossier),
        )
        self._shield_down_notifs[container] = nid

    async def _notify_shield_up(self, container: str, dossier: dict[str, str]) -> None:
        """Close the stale ShieldDown popup (if any) and post a brief confirmation."""
        if (down_nid := self._shield_down_notifs.pop(container, None)) is not None:
            try:
                await self._notifier.close(down_nid)
            except Exception:
                _log.exception("Failed to close stale ShieldDown notification %d", down_nid)
        label = _identity_label(dossier, container)
        await self._notifier.notify(
            f"Shield up: {label}",
            "Outbound firewall restored.",
            hints=_HINT_CONFIRMATION,
            timeout_ms=-1,
            container_id=container,
            **_notify_kwargs(dossier),
        )

    async def _notify_container_started(self, container: str, dossier: dict[str, str]) -> None:
        """Low-urgency, transient confirmation that a shielded container came online."""
        label = _identity_label(dossier, container)
        await self._notifier.notify(
            f"Container started: {label}",
            "",
            hints=_HINT_LIFECYCLE,
            timeout_ms=-1,
            container_id=container,
            **_notify_kwargs(dossier),
        )

    async def _notify_container_exited(
        self, container: str, reason: str, dossier: dict[str, str]
    ) -> None:
        """Low-urgency, transient confirmation that a shielded container stopped."""
        label = _identity_label(dossier, container)
        await self._notifier.notify(
            f"Container stopped: {label}",
            f"Reason: {reason}" if reason else "",
            hints=_HINT_LIFECYCLE,
            timeout_ms=-1,
            container_id=container,
            **_notify_kwargs(dossier),
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

    def _dispatch_lifecycle(self, method: str, *args: str) -> None:
        """Invoke a lifecycle hook on the notifier if it implements one.

        Notifiers that don't care (stock [`DbusNotifier`][terok_clearance.DbusNotifier],
        [`NullNotifier`][terok_clearance.NullNotifier]) don't expose the method; we no-op rather
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
