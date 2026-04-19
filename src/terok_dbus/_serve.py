# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shield clearance hub — owns ``org.terok.Shield1`` and dispatches verdicts.

Runs as a long-lived systemd user service.  Claims the Shield1 well-known
bus name so method calls from TUI / desktop-notifier consumers land here,
and delegates every verdict to the auditable ``terok-shield allow|deny``
CLI — the hub itself never mutates shield state directly.  Also hosts a
co-resident :class:`EventSubscriber` so blocked-connection signals land
as desktop notifications through the same D-Bus session.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import sys

from dbus_fast import BusType
from dbus_fast.aio import MessageBus
from dbus_fast.service import ServiceInterface, method, signal

from terok_dbus._interfaces import (
    SHIELD_BUS_NAME,
    SHIELD_INTERFACE_NAME,
    SHIELD_OBJECT_PATH,
)
from terok_dbus._notifier import DbusNotifier
from terok_dbus._null import NullNotifier
from terok_dbus._protocol import Notifier
from terok_dbus._subscriber import EventSubscriber

_log = logging.getLogger(__name__)


async def serve() -> None:
    """Run the hub service until SIGINT/SIGTERM.

    The hub owns ``org.terok.Shield1`` on the session bus and exposes the
    ``Verdict`` method.  It also starts a co-resident event subscriber so
    container-emitted ``ConnectionBlocked`` signals surface as desktop
    notifications — the subscriber's verdict callbacks round-trip through
    the bus and land in this same process's ``Verdict`` handler.
    """
    bus = await MessageBus(bus_type=BusType.SESSION).connect()

    hub = ShieldHub()
    bus.export(SHIELD_OBJECT_PATH, hub)
    await bus.request_name(SHIELD_BUS_NAME)
    _log.info("Shield1 hub online (%s)", SHIELD_BUS_NAME)

    notifier = await _desktop_notifier()
    subscriber = EventSubscriber(notifier, bus=bus)
    await subscriber.start()

    try:
        await _wait_for_shutdown_signal()
    finally:
        await subscriber.stop()
        await notifier.disconnect()
        bus.disconnect()


class ShieldHub(ServiceInterface):
    """The Shield1 service — dispatches verdicts and emits the applied ack.

    Verdicts are applied by shelling out to ``terok-shield allow|deny`` so
    the audited CLI remains the single trust boundary for nft / allowlist
    writes.  The hub itself is pure D-Bus plumbing: a method handler, an
    acknowledgement signal, and nothing else.  Container-emitted signals
    (``ConnectionBlocked``, ``ContainerStarted``, ``ContainerExited``) are
    fired by per-container readers via ``dbus-send`` and don't need to be
    declared on the hub's ServiceInterface.
    """

    def __init__(self) -> None:
        """Register the Shield1 interface under the canonical name."""
        super().__init__(SHIELD_INTERFACE_NAME)

    @method()
    async def Verdict(  # noqa: F821
        self, container: "s", request_id: "s", dest: "s", action: "s"
    ) -> "b":
        """Apply *action* to *dest*; emit ``VerdictApplied``; return success."""
        return await self._apply_verdict(container, request_id, dest, action)

    async def _apply_verdict(self, container: str, request_id: str, dest: str, action: str) -> bool:
        """Verdict-dispatch core — callable from tests without D-Bus roundtrip."""
        ok = False
        try:
            ok = await _run_shield_cli(container, dest, action)
        finally:
            self.VerdictApplied(container, request_id, action, ok)
        return ok

    @signal()
    def VerdictApplied(  # noqa: F821
        self, container: "s", request_id: "s", action: "s", ok: "b"
    ) -> "sssb":  # pragma: no cover
        """Acknowledge that *action* on *request_id* was applied (or not)."""
        return [container, request_id, action, ok]


# ── Verdict execution ────────────────────────────────────────────────


async def _run_shield_cli(container: str, dest: str, action: str) -> bool:
    """Invoke ``terok-shield allow|deny <container> <dest>`` and await completion."""
    if action not in {"allow", "deny"}:
        _log.warning("Unknown verdict action %r — ignored", action)
        return False
    if not dest:
        _log.warning("Verdict missing dest — nothing to apply")
        return False
    shield_bin = shutil.which("terok-shield")
    if not shield_bin:
        _log.error("terok-shield not on PATH — cannot apply verdict")
        return False
    proc = await asyncio.create_subprocess_exec(
        shield_bin,
        action,
        container,
        dest,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )
    stderr = await proc.stderr.read() if proc.stderr else b""
    returncode = await proc.wait()
    if returncode != 0:
        _log.warning("shield %s failed: %s", action, stderr.decode(errors="replace").strip())
    return returncode == 0


# ── Notifier selection ───────────────────────────────────────────────


async def _desktop_notifier() -> Notifier:
    """Prefer a real D-Bus notifier; fall through to null on headless hosts."""
    notifier = DbusNotifier("terok-shield")
    try:
        await notifier._connect()
    except Exception as exc:  # noqa: BLE001
        _log.info("freedesktop Notifications unavailable (%s) — skipping desktop UI", exc)
        return NullNotifier()
    return notifier


# ── Shutdown plumbing ────────────────────────────────────────────────


async def _wait_for_shutdown_signal() -> None:
    """Block until SIGINT/SIGTERM arrives so systemd can stop the unit cleanly."""
    import signal as signalmod

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signalmod.SIGINT, signalmod.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()


# ── CLI stdout bootstrapper (called from _registry._handle_serve) ────


def _configure_logging() -> None:
    """Send INFO-level logs to stderr so journald / systemd pick them up."""
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        level=logging.INFO,
        stream=sys.stderr,
    )
