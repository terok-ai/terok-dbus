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
import contextlib
import logging
import shutil
import sys
from collections.abc import Awaitable, Callable

from dbus_fast import BusType, RequestNameReply
from dbus_fast.aio import MessageBus
from dbus_fast.service import ServiceInterface, method, signal

from terok_dbus._event_ingester import EventIngester, default_socket_path
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

#: Seconds before ``_desktop_notifier`` gives up on the freedesktop
#: Notifications connect and falls through to the null notifier.  A live
#: session answers in tens of milliseconds; anything slower than this is a
#: host-health signal, not normal behaviour.
_NOTIFIER_CONNECT_TIMEOUT_S = 2.0

#: Seconds granted to each individual cleanup step in the shutdown finally
#: block (ingester stop, subscriber stop, notifier disconnect).  Prevents
#: one hung bus call from burning systemd's stop-sigterm deadline.
_CLEANUP_STEP_TIMEOUT_S = 2.0

#: Upper bound on how long a single ``terok-shield allow|deny`` invocation
#: may take.  Bounded so a hung shield (nft lock contention, crashed podman
#: pause, slow setns) can't pin an RPC method call forever — D-Bus clients
#: have their own reply timeout, and we want our ``VerdictApplied`` signal
#: to go out in time to tell the caller the verdict actually failed.
_SHIELD_CLI_TIMEOUT_S = 10.0


async def serve() -> None:  # pragma: no cover — integration path, real session bus
    """Run the hub service until SIGINT/SIGTERM.

    The hub owns ``org.terok.Shield1`` on the session bus and exposes the
    ``Verdict`` method.  It also starts a co-resident event subscriber so
    container-emitted ``ConnectionBlocked`` signals surface as desktop
    notifications — the subscriber's verdict callbacks round-trip through
    the bus and land in this same process's ``Verdict`` handler.

    No-cover because the happy path requires a real session bus and a
    live Notifications daemon.  The per-step helpers
    (``_make_event_sink``, ``_cleanup_with_timeout``, ``_desktop_notifier``)
    are covered individually; an ``TestServeRequestName`` test covers the
    one error path (non-PRIMARY-OWNER) with a mocked bus to lock in
    fail-fast on name collisions.
    """
    bus = await MessageBus(bus_type=BusType.SESSION).connect()
    hub = ShieldHub()
    await _claim_bus_name(bus, hub)

    notifier = await _desktop_notifier()
    subscriber = EventSubscriber(notifier, bus=bus)
    await subscriber.start()

    ingester = EventIngester(
        socket_path=default_socket_path(),
        on_event=_make_event_sink(hub),
    )
    await ingester.start()

    try:
        await _wait_for_shutdown_signal()
    finally:
        await _cleanup_with_timeout(ingester, subscriber, notifier, bus)


async def _claim_bus_name(bus: MessageBus, hub: "ShieldHub") -> None:
    """Export the hub and take primary ownership of ``org.terok.Shield1``.

    A non-PRIMARY reply would leave the new process sitting in the queue
    while every ``Verdict`` method call routes to the pre-existing owner —
    operators see a live service that never applies their clicks.  Fail
    fast so the stale hub is the one visible culprit.
    """
    bus.export(SHIELD_OBJECT_PATH, hub)
    reply = await bus.request_name(SHIELD_BUS_NAME)
    if reply is not RequestNameReply.PRIMARY_OWNER:
        bus.disconnect()
        raise RuntimeError(
            f"could not claim {SHIELD_BUS_NAME}: reply={reply.name} — "
            "is another terok-dbus instance already running?"
        )
    _log.info("Shield1 hub online (%s)", SHIELD_BUS_NAME)


async def _cleanup_with_timeout(
    ingester: EventIngester,
    subscriber: EventSubscriber,
    notifier: Notifier,
    bus: MessageBus,
) -> None:
    """Run each cleanup step under a short timeout so SIGTERM always exits cleanly.

    Individual steps can hang on a flaky session bus (a freedesktop
    Notifications daemon that stops responding mid-teardown, a subscriber
    signal-match removal that waits forever for an ack).  Without a cap,
    systemd waits out its stop-sigterm deadline and has to escalate to
    SIGABRT — that's how ``terok setup`` ends up spending 40+ seconds on
    the hub restart.  Five seconds per step is plenty for a healthy bus,
    and if we hit the cap the OS kills us which is fine because the
    process is exiting anyway.
    """
    for step in (
        ("ingester", ingester.stop()),
        ("subscriber", subscriber.stop()),
        ("notifier", notifier.disconnect()),
    ):
        name, awaitable = step
        try:
            await asyncio.wait_for(awaitable, timeout=_CLEANUP_STEP_TIMEOUT_S)
        except Exception as exc:  # noqa: BLE001 — shutdown must continue past any step
            _log.warning(
                "hub shutdown: %s did not finish within %gs (%s)",
                name,
                _CLEANUP_STEP_TIMEOUT_S,
                exc,
            )
    with contextlib.suppress(Exception):
        bus.disconnect()


def _make_event_sink(hub: "ShieldHub") -> "Callable[[dict], Awaitable[None]]":
    """Return an async sink that relays reader events onto the hub's signals.

    Each event ``type`` maps to one emission; unknown types are ignored so
    the wire format can grow without breaking old hubs.  KeyError on a
    malformed event is caught by the ingester's dispatch loop and logged,
    so one missing field won't kill the relay.
    """

    async def sink(event: dict) -> None:
        kind = event.get("type")
        if kind == "pending":
            hub.ConnectionBlocked(
                event["container"],
                event["id"],
                event["dest"],
                int(event["port"]),
                int(event["proto"]),
                event.get("domain", ""),
            )
        elif kind == "container_started":
            hub.ContainerStarted(event["container"])
        elif kind == "container_exited":
            hub.ContainerExited(event["container"], event.get("reason", ""))

    return sink


class ShieldHub(ServiceInterface):
    """The Shield1 service — dispatches verdicts and emits container events.

    Verdicts are applied by shelling out to ``terok-shield allow|deny`` so
    the audited CLI remains the single trust boundary for nft / allowlist
    writes.  ``Container*`` and ``ConnectionBlocked`` signals originate
    from per-container NFLOG readers that stream JSON to the hub over a
    unix socket (see :class:`EventIngester`); the hub emits them onto the
    session bus from here, where peer-credential auth against the session
    dbus-daemon still succeeds — the readers themselves live in
    ``NS_ROOTLESS`` and can't reach the session bus directly.
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

    @signal()
    def ConnectionBlocked(  # noqa: F821
        self,
        container: "s",
        request_id: "s",
        dest: "s",
        port: "u",
        proto: "u",
        domain: "s",
    ) -> "sssuus":  # pragma: no cover
        """Republish a block event the hub received from a container reader."""
        return [container, request_id, dest, port, proto, domain]

    @signal()
    def ContainerStarted(self, container: "s") -> "s":  # noqa: F821  # pragma: no cover
        """Announce that a container's reader came online."""
        return container

    @signal()
    def ContainerExited(self, container: "s", reason: "s") -> "ss":  # noqa: F821  # pragma: no cover
        """Announce that a container's reader went away."""
        return [container, reason]


# ── Verdict execution ────────────────────────────────────────────────


async def _run_shield_cli(container: str, dest: str, action: str) -> bool:
    """Invoke ``terok-shield allow|deny <container> <dest>`` and await completion.

    The subprocess has a hard timeout and swallows spawn errors so a hung
    or missing shield binary surfaces as ``VerdictApplied ok=false`` rather
    than propagating an OSError / TimeoutError up into the D-Bus method
    reply (which would arrive as a cryptic ``org.freedesktop.DBus.Error.Failed``
    in the caller's client, with no signal to drive the notification
    replacement).  Clean ``False`` is much easier to handle everywhere
    downstream.
    """
    if action not in {"allow", "deny"}:
        _log.warning("Unknown verdict action %r — ignored", action)
        return False
    if not dest:
        _log.warning("Verdict missing dest — nothing to apply")
        return False
    shield_bin = _find_shield_binary()
    if not shield_bin:
        _log.error("terok-shield not found (neither in venv bin nor on PATH)")
        return False
    try:
        proc = await asyncio.create_subprocess_exec(
            shield_bin,
            action,
            container,
            dest,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as exc:
        _log.error("failed to spawn terok-shield: %s", exc)
        return False
    try:
        _, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=_SHIELD_CLI_TIMEOUT_S)
    except TimeoutError:
        proc.kill()
        with contextlib.suppress(Exception):
            await proc.communicate()
        _log.warning("shield %s timed out after %gs", action, _SHIELD_CLI_TIMEOUT_S)
        return False
    returncode = proc.returncode
    if returncode != 0:
        _log.warning("shield %s failed: %s", action, stderr_bytes.decode(errors="replace").strip())
    return returncode == 0


def _find_shield_binary() -> str | None:
    """Locate the ``terok-shield`` entry point the hub should shell out to.

    systemd user units inherit a minimal ``PATH`` (``/usr/local/bin:/usr/bin:/bin``),
    which normally excludes the user's ``~/.local/bin`` and any pipx venv's
    ``bin/``.  Look for a sibling launcher in the same venv as this hub
    process first — pipx installs all of terok's entry points side-by-side,
    so if we were installed that way, ``terok-shield`` is right next to
    our own executable.  Fall through to ``shutil.which`` for dev installs
    where ``PATH`` is curated.
    """
    from pathlib import Path

    sibling = Path(sys.executable).parent / "terok-shield"
    if sibling.is_file():
        return str(sibling)
    return shutil.which("terok-shield")


# ── Notifier selection ───────────────────────────────────────────────


async def _desktop_notifier() -> Notifier:
    """Prefer a real D-Bus notifier; fall through to null on headless / slow hosts.

    Bound the connect at two seconds so a live desktop session doesn't have
    to wait for dbus-daemon's default round-trip timeout.  We distinguish
    three outcomes so the log reflects what actually happened:

    * **Connected.** Use the real notifier.
    * **Timed out.** The Notifications interface *does* exist on the bus
      (otherwise the call would fail fast with NotFound/NoReply) but isn't
      answering in time.  Emit a WARNING — something is wrong on this host;
      the operator should investigate.
    * **Actually unavailable.** No service registers the Notifications
      interface at all — headless box, CI container, minimal session.
      INFO is right: expected and routine, no action required.

    Verdict dispatch still works through the ``NullNotifier`` fallback in
    both failure cases; the log-level split is purely to help the operator
    tell "works as designed" apart from "fix your desktop stack".
    """
    notifier = DbusNotifier("terok-shield")
    try:
        await asyncio.wait_for(notifier.connect(), timeout=_NOTIFIER_CONNECT_TIMEOUT_S)
    except TimeoutError:
        _log.warning(
            "freedesktop Notifications timed out after %gs — desktop UI skipped, "
            "investigate dbus-daemon / notification daemon health",
            _NOTIFIER_CONNECT_TIMEOUT_S,
        )
        return NullNotifier()
    except Exception as exc:  # noqa: BLE001
        _log.info("freedesktop Notifications unavailable (%s) — skipping desktop UI", exc)
        return NullNotifier()
    return notifier


# ── Shutdown plumbing ────────────────────────────────────────────────


async def _wait_for_shutdown_signal() -> None:  # pragma: no cover — real signal delivery
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
