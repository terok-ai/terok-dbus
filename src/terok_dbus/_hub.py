# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""The clearance hub — varlink server + reader ingester + verdict exec.

Fans reader-emitted events (blocks, container lifecycle, shield state)
out to every connected clearance client, and applies verdicts the
clients send back by shelling out to ``terok-shield allow|deny``.  The
only D-Bus in sight is what individual clients choose to use on their
own (the desktop notifier reaches for ``org.freedesktop.Notifications``
out-of-band); the hub itself speaks plain unix-socket varlink.

Authorisation is structural: the socket is mode 0600 (same-UID only),
and every ``Verdict`` call must cite a ``(container, request_id, dest)``
triple the hub actually emitted via ``connection_blocked``.  The
triple is recorded at emit time and dropped on verdict or lifecycle
change; anything that doesn't match is a :class:`UnknownRequest` or
:class:`VerdictTupleMismatch` refusal.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import shutil
import stat
import sys
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path

from asyncvarlink import VarlinkInterfaceRegistry, create_unix_server
from asyncvarlink.serviceinterface import VarlinkServiceInterface

from terok_dbus._event_ingester import EventIngester
from terok_dbus._wire import (
    Clearance1Interface,
    ClearanceEvent,
    InvalidAction,
    ShieldCliFailed,
    UnknownRequest,
    VerdictTupleMismatch,
)

_log = logging.getLogger(__name__)

#: Upper bound on a single ``terok-shield allow|deny`` invocation.  Shield
#: holds an nft lock and can also block on a slow podman pause; clients
#: have their own reply timeout, so failing-fast here surfaces the real
#: outcome (ShieldCliFailed) instead of letting the method call hang.
_SHIELD_CLI_TIMEOUT_S = 10.0

#: Cap stderr bytes we forward into a :class:`ShieldCliFailed` error.
#: Desktop popups can't render multi-kilobyte bodies; clients also tend
#: to truncate.  Prevents a shield crash dump from travelling end-to-end
#: as a varlink error parameter.
_STDERR_CAP_BYTES = 512

#: Depth of per-subscriber event queues.  Slow subscribers don't block
#: fan-out to other clients — the hub drops their oldest events once
#: this limit is reached.  Desktop popups + TUI rows are an instant-ish
#: render surface, so a modest depth is plenty; keeping the queue
#: bounded also prevents a stuck client from pinning arbitrary memory.
_SUBSCRIBER_QUEUE_DEPTH = 128

#: Canonical clearance-socket basename, under ``$XDG_RUNTIME_DIR``.
_CLEARANCE_SOCKET_BASENAME = "terok-clearance.sock"


def default_clearance_socket_path() -> Path:
    """Return the canonical clearance-socket path under ``$XDG_RUNTIME_DIR``."""
    xdg = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    return Path(xdg) / _CLEARANCE_SOCKET_BASENAME


@dataclass
class _LiveVerdict:
    """One outstanding block the hub has authorised for a future ``Verdict`` call."""

    container: str
    dest: str


#: Reader ``type`` → the ``ClearanceEvent.type`` value we emit downstream.
#: A single mapping stands in for what used to be a catalog of per-event
#: emitters; the event shape is flat enough that translation is a
#: straightforward dict-copy with a renamed discriminator.
_READER_EVENT_TYPES: dict[str, str] = {
    "pending": "connection_blocked",
    "container_started": "container_started",
    "container_exited": "container_exited",
    "shield_up": "shield_up",
    "shield_down": "shield_down",
    "shield_down_all": "shield_down_all",
}


class ClearanceHub:
    """Server for the ``org.terok.Clearance1`` interface.

    Owns three pieces of state:

    * ``_subscribers`` — a set of bounded per-connection queues; the hub
      puts a :class:`ClearanceEvent` on each one every time the reader
      ingester delivers an event.  Slow clients see their oldest events
      dropped; fast clients aren't affected.
    * ``_live_verdicts`` — the ``request_id → (container, dest)`` map
      the ``Verdict`` method checks for the authz binding.
    * An :class:`EventIngester` bound to the canonical reader socket.

    Lifecycle: :meth:`start` brings everything up; :meth:`stop` tears
    it down under individual timeouts so a flaky bus or a stuck
    subscriber can't burn systemd's stop-sigterm deadline.
    """

    def __init__(
        self,
        *,
        clearance_socket: Path | None = None,
        reader_socket: Path | None = None,
        shield_binary: str | None = None,
    ) -> None:
        """Configure the two sockets and the shield executable path."""
        self._clearance_socket = clearance_socket or default_clearance_socket_path()
        self._reader_socket = reader_socket  # None → EventIngester picks its default.
        self._shield_binary = shield_binary or _find_shield_binary()

        self._subscribers: set[asyncio.Queue[ClearanceEvent]] = set()
        self._live_verdicts: dict[str, _LiveVerdict] = {}

        self._ingester: EventIngester | None = None
        self._varlink_server: object | None = None  # asyncvarlink's UnixServer

    # ── lifecycle ──────────────────────────────────────────────────────

    async def start(self) -> None:
        """Bring the ingester + varlink server online and accept clients."""
        self._ingester = EventIngester(
            socket_path=self._reader_socket or _default_reader_socket(),
            on_event=self._relay_reader_event,
        )
        await self._ingester.start()

        registry = VarlinkInterfaceRegistry()
        registry.register_interface(
            Clearance1Interface(
                event_stream_factory=self._subscribe,
                apply_verdict=self._apply_verdict,
            )
        )
        registry.register_interface(
            VarlinkServiceInterface(
                vendor="terok",
                product="terok-dbus",
                version=_own_version(),
                url="https://github.com/terok-ai/terok-dbus",
                registry=registry,
            )
        )

        # Harden the clearance socket the same way the reader socket does:
        # private parent, 0600 mode via umask, post-bind lstat.
        _ensure_private_parent(self._clearance_socket)
        with contextlib.suppress(FileNotFoundError):
            self._clearance_socket.unlink()
        old_umask = os.umask(0o177)
        try:
            self._varlink_server = await create_unix_server(
                registry.protocol_factory, path=str(self._clearance_socket)
            )
        finally:
            os.umask(old_umask)
        lst = os.lstat(self._clearance_socket)
        if not stat.S_ISSOCK(lst.st_mode):
            raise RuntimeError(
                f"clearance path is not a socket after bind: {self._clearance_socket}"
            )
        _log.info("clearance hub online at %s", self._clearance_socket)

    async def stop(self) -> None:
        """Close the varlink server + ingester; drain subscriber queues."""
        if self._varlink_server is not None:
            self._varlink_server.close()
            # ``wait_closed`` can block forever if a subscriber connection
            # is mid-generator — cap it so a flaky client doesn't burn
            # systemd's stop-sigterm deadline.
            with contextlib.suppress(TimeoutError, Exception):
                await asyncio.wait_for(self._varlink_server.wait_closed(), timeout=1.0)
            self._varlink_server = None
        if self._ingester is not None:
            with contextlib.suppress(Exception):
                await self._ingester.stop()
            self._ingester = None
        # Wake every subscriber so its generator exits promptly rather than
        # leaking a hanging task into the event loop.
        for queue in list(self._subscribers):
            queue.put_nowait(_SENTINEL)
        self._subscribers.clear()
        self._live_verdicts.clear()

    # ── reader ingestion ───────────────────────────────────────────────

    async def _relay_reader_event(self, raw: dict) -> None:
        """Translate one ingester dict → a :class:`ClearanceEvent` + fan it out.

        Records the authz binding on ``connection_blocked`` events and
        releases it on ``verdict_applied`` / lifecycle changes, so the
        ``Verdict`` method can pass or refuse without re-consulting the
        reader.  Malformed events are logged and dropped — one bad line
        from a rogue reader mustn't kill the ingester.
        """
        wire_type = _READER_EVENT_TYPES.get(raw.get("type", ""))
        if wire_type is None:
            _log.debug("dropping unknown reader event type %r", raw.get("type"))
            return
        try:
            event = _translate_reader_event(wire_type, raw)
        except (KeyError, ValueError, TypeError) as exc:
            _log.warning("dropping malformed reader event %r: %s", raw, exc)
            return
        self._update_live_verdicts(event)
        self._fan_out(event)

    def _update_live_verdicts(self, event: ClearanceEvent) -> None:
        """Maintain the authz-binding map in lockstep with the event stream.

        The bound ``dest`` is the "target" shield will actually operate
        on — the domain when the reader resolved one via dnsmasq (shield
        dispatches ``allow_domain`` on shape so future DNS rotations
        track), else the raw IP.  Clients send the same value back as
        ``Verdict.dest``; binding on anything else would force a
        pointless translation pass on every verdict.
        """
        if event.type == "connection_blocked" and event.request_id:
            self._live_verdicts[event.request_id] = _LiveVerdict(
                container=event.container,
                dest=event.domain or event.dest,
            )
        elif event.type in {"shield_down", "shield_down_all", "container_exited"}:
            # Stale blocks: verdicts on them would write into an allowlist
            # no-one is consulting right now.  Drop so a later same-container
            # block starts a fresh pending entry.
            stale = [
                rid
                for rid, live in self._live_verdicts.items()
                if live.container == event.container
            ]
            for rid in stale:
                self._live_verdicts.pop(rid, None)

    def _fan_out(self, event: ClearanceEvent) -> None:
        """Push *event* to every subscriber queue, dropping oldest on overflow."""
        for queue in list(self._subscribers):
            if queue.full():
                with contextlib.suppress(asyncio.QueueEmpty):
                    queue.get_nowait()
            queue.put_nowait(event)

    # ── varlink method implementations ─────────────────────────────────

    async def _subscribe(self) -> AsyncIterator[ClearanceEvent]:
        """Create a per-connection queue and yield events until the client goes."""
        queue: asyncio.Queue[ClearanceEvent] = asyncio.Queue(maxsize=_SUBSCRIBER_QUEUE_DEPTH)
        self._subscribers.add(queue)
        try:
            while True:
                event = await queue.get()
                if event is _SENTINEL:
                    return
                yield event
        finally:
            self._subscribers.discard(queue)

    async def _apply_verdict(self, container: str, request_id: str, dest: str, action: str) -> bool:
        """Validate the triple, shell out to ``terok-shield``, emit VerdictApplied.

        Raises :class:`InvalidAction` / :class:`UnknownRequest` /
        :class:`VerdictTupleMismatch` / :class:`ShieldCliFailed` on the
        four refusal paths; returns ``True`` only when the shield
        invocation itself succeeded.  The ``verdict_applied`` event
        emitted on the shared fan-out carries the same ``ok`` value so
        every subscriber (including the one that called us) sees the
        same outcome.
        """
        if action not in {"allow", "deny"}:
            raise InvalidAction(action=action)
        live = self._live_verdicts.pop(request_id, None)
        if live is None:
            raise UnknownRequest(request_id=request_id)
        if live.container != container or live.dest != dest:
            # Put it back — a later legitimate verdict on the same request
            # should still be accepted, so this call's mismatch mustn't
            # consume the entry.
            self._live_verdicts[request_id] = live
            raise VerdictTupleMismatch(
                expected_container=live.container,
                expected_dest=live.dest,
                got_container=container,
                got_dest=dest,
            )

        ok, stderr_snippet = await self._run_shield(container, dest, action)
        # Republish the outcome on the event stream so every subscriber
        # (not just this caller) can flip its notification state.
        self._fan_out(
            ClearanceEvent(
                type="verdict_applied",
                container=container,
                request_id=request_id,
                action=action,
                ok=ok,
            )
        )
        if not ok:
            raise ShieldCliFailed(action=action, stderr=stderr_snippet)
        return True

    async def _run_shield(self, container: str, dest: str, action: str) -> tuple[bool, str]:
        """Invoke ``terok-shield allow|deny``; return ``(ok, stderr_snippet)``.

        Bounded by :data:`_SHIELD_CLI_TIMEOUT_S`.  Spawn errors, non-zero
        exit, and timeouts all fold into ``(False, reason)`` so callers
        see one shape regardless of how shield misbehaved.
        """
        if not self._shield_binary:
            return False, "terok-shield not found on PATH"
        try:
            proc = await asyncio.create_subprocess_exec(
                self._shield_binary,
                action,
                container,
                dest,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:
            _log.error("failed to spawn terok-shield: %s", exc)
            return False, f"spawn failed: {exc}"
        try:
            _, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=_SHIELD_CLI_TIMEOUT_S
            )
        except TimeoutError:
            proc.kill()
            with contextlib.suppress(Exception):
                await proc.communicate()
            _log.warning("shield %s timed out after %gs", action, _SHIELD_CLI_TIMEOUT_S)
            return False, f"timed out after {_SHIELD_CLI_TIMEOUT_S}s"
        snippet = (stderr_bytes[:_STDERR_CAP_BYTES] or b"").decode(errors="replace").strip()
        ok = proc.returncode == 0
        if not ok:
            _log.warning("shield %s failed: %s", action, snippet)
        return ok, snippet


# ── module-level helpers ───────────────────────────────────────────────


class _Sentinel:
    """Marker pushed onto subscriber queues to cleanly exit their generators."""


_SENTINEL = _Sentinel()


def _translate_reader_event(wire_type: str, raw: dict) -> ClearanceEvent:
    """Build a :class:`ClearanceEvent` from an ingester-parsed dict.

    The ingester already decodes JSON; this just moves fields around
    into the typed shape and normalises missing values.  Keyed by
    ``wire_type`` so each kind gets exactly the fields it needs.
    """
    container = str(raw["container"])
    if wire_type == "connection_blocked":
        return ClearanceEvent(
            type=wire_type,
            container=container,
            request_id=str(raw["id"]),
            dest=str(raw["dest"]),
            port=int(raw["port"]),
            proto=int(raw["proto"]),
            domain=str(raw.get("domain", "")),
        )
    if wire_type == "container_exited":
        return ClearanceEvent(
            type=wire_type,
            container=container,
            reason=str(raw.get("reason", "")),
        )
    return ClearanceEvent(type=wire_type, container=container)


def _find_shield_binary() -> str | None:
    """Locate ``terok-shield`` — sibling venv first, then PATH, then ``None``."""
    sibling = Path(sys.executable).parent / "terok-shield"
    if sibling.is_file():
        return str(sibling)
    return shutil.which("terok-shield")


def _own_version() -> str:
    """Return our package version for varlink ``GetInfo`` — best-effort."""
    try:
        from importlib.metadata import version

        return version("terok-dbus")
    except Exception:  # pragma: no cover — only hits if metadata is missing
        return "0.0.0"


def _default_reader_socket() -> Path:
    """The EventIngester's default path, re-derived for the hub's wiring."""
    from terok_dbus._event_ingester import default_socket_path

    return default_socket_path()


def _ensure_private_parent(path: Path) -> None:
    """Refuse to bind under a parent dir that isn't owned by us + mode 0700-ish."""
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    st = parent.stat()
    if st.st_uid != os.getuid():
        raise RuntimeError(
            f"clearance parent dir not owned by current uid: {parent} (owner uid={st.st_uid})"
        )
    if st.st_mode & 0o077:
        raise RuntimeError(
            f"clearance parent dir is group/world accessible: "
            f"{parent} (mode={oct(st.st_mode & 0o777)})"
        )


# ── stdout bootstrapper (called from _registry._handle_serve) ──────────


async def serve() -> None:  # pragma: no cover — integration path
    """Run the hub service until SIGINT/SIGTERM.

    The entry point ``terok-dbus serve`` hands off here.  Blocks forever
    on a signal-set :class:`asyncio.Event`; systemd's SIGTERM flips it,
    then :meth:`stop` tears down the server under a timeout.
    """
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        level=logging.INFO,
        stream=sys.stderr,
    )
    hub = ClearanceHub()
    await hub.start()
    try:
        await _wait_for_shutdown_signal()
    finally:
        await hub.stop()


async def _wait_for_shutdown_signal() -> None:  # pragma: no cover
    """Block until SIGINT/SIGTERM arrives."""
    import signal as signalmod

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signalmod.SIGINT, signalmod.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()
