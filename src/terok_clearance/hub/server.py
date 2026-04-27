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
change; anything that doesn't match is a [`UnknownRequest`][terok_clearance.hub.server.UnknownRequest] or
[`VerdictTupleMismatch`][terok_clearance.hub.server.VerdictTupleMismatch] refusal.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from pathlib import Path

from asyncvarlink import VarlinkInterfaceRegistry, create_unix_server
from asyncvarlink.serviceinterface import VarlinkServiceInterface

from terok_clearance.domain.events import ClearanceEvent
from terok_clearance.hub.ingester import EventIngester
from terok_clearance.verdict.client import VerdictClient
from terok_clearance.wire.errors import (
    InvalidAction,
    ShieldCliFailed,
    UnknownRequest,
    VerdictTupleMismatch,
)
from terok_clearance.wire.interface import Clearance1Interface
from terok_clearance.wire.socket import default_clearance_socket_path

_log = logging.getLogger(__name__)

#: Depth of per-subscriber event queues.  Slow subscribers don't block
#: fan-out to other clients — the hub drops their oldest events once
#: this limit is reached.  Desktop popups + TUI rows are an instant-ish
#: render surface, so a modest depth is plenty; keeping the queue
#: bounded also prevents a stuck client from pinning arbitrary memory.
_SUBSCRIBER_QUEUE_DEPTH = 128

#: Reader ``type`` → wire-level ``ClearanceEvent.type``.  Only one event
#: renames (``pending → connection_blocked``); every other reader type
#: flows through unchanged.  Kept as an explicit allowlist so unknown
#: values get dropped at `ClearanceHub._relay_reader_event` rather
#: than leaking to clients.
_WIRE_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "container_started",
        "container_exited",
        "shield_up",
        "shield_down",
        "shield_down_all",
    }
)


class ClearanceHub:
    """Server for the ``org.terok.Clearance1`` interface.

    Owns three pieces of state:

    * ``_subscribers`` — a set of bounded per-connection queues; the hub
      puts a [`ClearanceEvent`][terok_clearance.ClearanceEvent] on each one every time the reader
      ingester delivers an event.  Slow clients see their oldest events
      dropped; fast clients aren't affected.
    * ``_live_verdicts`` — the ``request_id → (container, dest)`` map
      the ``Verdict`` method checks for the authz binding.
    * An [`EventIngester`][terok_clearance.hub.ingester.EventIngester] bound to the canonical reader socket.

    Lifecycle: [`start`][terok_clearance.hub.server.ClearanceHub.start] brings everything up; [`stop`][terok_clearance.hub.server.ClearanceHub.stop] tears
    it down under individual timeouts so a flaky bus or a stuck
    subscriber can't burn systemd's stop-sigterm deadline.
    """

    def __init__(
        self,
        *,
        clearance_socket: Path | None = None,
        reader_socket: Path | None = None,
        verdict_client: VerdictClient | None = None,
    ) -> None:
        """Configure the two sockets and the verdict-helper client.

        ``verdict_client`` is injected so tests can stub out shield exec
        without spawning the helper process.  Production callers leave
        it defaulted — a fresh [`VerdictClient`][terok_clearance.hub.server.VerdictClient] pointing at the
        canonical helper socket.
        """
        self._clearance_socket = clearance_socket or default_clearance_socket_path()
        self._reader_socket = reader_socket  # None → EventIngester picks its default.
        self._verdict_client = verdict_client or VerdictClient()

        self._subscribers: set[asyncio.Queue[ClearanceEvent]] = set()
        # request_id → (container, dest) the hub emitted in the matching
        # ConnectionBlocked; Verdict calls must cite a triple that matches.
        self._live_verdicts: dict[str, tuple[str, str]] = {}

        self._ingester: EventIngester | None = None
        self._varlink_server: object | None = None  # asyncvarlink's UnixServer

    # ── lifecycle ──────────────────────────────────────────────────────

    async def start(self) -> None:
        """Bring the ingester + varlink server online and accept clients.

        Transactional: if the varlink bind fails after the ingester is
        already listening, the ingester is stopped before the exception
        propagates so a half-started hub doesn't leak a live
        reader-side socket on systemd restart paths.
        """
        self._ingester = EventIngester(
            socket_path=self._reader_socket or _default_reader_socket(),
            on_event=self._relay_reader_event,
        )
        await self._ingester.start()
        try:
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
                    product="terok-clearance",
                    version=_own_version(),
                    url="https://github.com/terok-ai/terok-clearance",
                    registry=registry,
                )
            )

            from terok_clearance.wire.socket import bind_hardened

            async def _factory(path: str) -> object:
                return await create_unix_server(registry.protocol_factory, path=path)

            self._varlink_server = await bind_hardened(
                _factory, self._clearance_socket, "clearance"
            )
        except BaseException:
            with contextlib.suppress(Exception):
                await self._ingester.stop()
            self._ingester = None
            raise
        _log.info("clearance hub online at %s", self._clearance_socket)

    async def stop(self) -> None:
        """Close the varlink server + ingester; drain subscriber queues."""
        if self._varlink_server is not None:
            # ``close()`` on its own only stops accepting new connections;
            # existing subscribers would sit forever in ``queue.get()`` and
            # ``wait_closed`` would hang until the timeout fires.
            # ``close_clients()`` walks the live transports and closes them,
            # which makes the server-side ``_call_async_method_more``'s
            # next ``send_reply`` fail with OSError — that in turn calls
            # ``generator.aclose()`` on the subscriber, propagating cleanly
            # through to our ``finally`` block.  This avoids the
            # assertion asyncvarlink fires when a streaming generator
            # ends "normally" with ``continues=True`` on the last reply.
            self._varlink_server.close()
            with contextlib.suppress(AttributeError):
                self._varlink_server.close_clients()
            with contextlib.suppress(TimeoutError, Exception):
                await asyncio.wait_for(self._varlink_server.wait_closed(), timeout=1.0)
            self._varlink_server = None
        if self._ingester is not None:
            with contextlib.suppress(Exception):
                await self._ingester.stop()
            self._ingester = None
        with contextlib.suppress(Exception):
            await self._verdict_client.stop()
        self._subscribers.clear()
        self._live_verdicts.clear()

    # ── reader ingestion ───────────────────────────────────────────────

    async def _relay_reader_event(self, raw: dict) -> None:  # NOSONAR S7503
        """Translate one ingester dict → a [`ClearanceEvent`][terok_clearance.ClearanceEvent] + fan it out.

        Records the authz binding on ``connection_blocked`` events and
        releases it on ``verdict_applied`` / lifecycle changes, so the
        ``Verdict`` method can pass or refuse without re-consulting the
        reader.  Malformed events are logged and dropped — one bad line
        from a rogue reader mustn't kill the ingester.
        """
        raw_type = raw.get("type", "")
        # Only the ``pending → connection_blocked`` renaming differs;
        # every other reader type flows through with the same name.
        wire_type = "connection_blocked" if raw_type == "pending" else raw_type
        if wire_type != "connection_blocked" and wire_type not in _WIRE_EVENT_TYPES:
            _log.debug("dropping unknown reader event type %r", raw_type)
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
            self._live_verdicts[event.request_id] = (
                event.container,
                event.domain or event.dest,
            )
        elif event.type in {"shield_down", "shield_down_all", "container_exited"}:
            stale = [
                rid
                for rid, (container, _) in self._live_verdicts.items()
                if container == event.container
            ]
            for rid in stale:
                self._live_verdicts.pop(rid, None)

    def _fan_out(self, event: ClearanceEvent) -> None:
        """Push *event* to every subscriber queue, dropping oldest on overflow.

        Iterates ``self._subscribers`` directly — the loop body can't
        yield (no ``await``), so no other coroutine can mutate the set
        between iterations and a defensive copy would be pointless.
        """
        for queue in self._subscribers:
            if queue.full():
                with contextlib.suppress(asyncio.QueueEmpty):
                    queue.get_nowait()
            queue.put_nowait(event)

    # ── varlink method implementations ─────────────────────────────────

    async def _subscribe(self) -> AsyncIterator[ClearanceEvent]:
        """Create a per-connection queue and yield events until the client goes.

        The generator is never expected to terminate on its own — ending
        "normally" with ``delay_generator=False`` trips the asyncvarlink
        server-protocol ``assert not continues`` because every yield
        leaves ``continues=True``.  Shutdown runs through
        [`stop`][terok_clearance.hub.server.ClearanceHub.stop]'s ``close_clients()`` instead, which triggers a
        send_reply OSError and a clean ``generator.aclose()`` into the
        ``finally`` block below.

        Known-benign shutdown noise: on Python 3.14 the stop path can
        still log ``ERROR asyncio: Exception in callback
        VarlinkServerProtocol._on_receiver_completes(): CancelledError``.
        That's an asyncvarlink × 3.14 interaction — asyncio.run cancels
        the in-flight handler task, ``CancelledError`` propagates
        through our ``yield await queue.get()``, asyncvarlink's
        completion callback then does ``call_fut.exception()`` which
        in 3.14 re-raises on a cancelled future (older Pythons
        returned ``None``).  Purely cosmetic; the hub has already
        stopped cleanly by the time it logs.  Revisit once
        asyncvarlink wraps that ``exception()`` call in
        ``try/except CancelledError``.
        """
        queue: asyncio.Queue[ClearanceEvent] = asyncio.Queue(maxsize=_SUBSCRIBER_QUEUE_DEPTH)
        self._subscribers.add(queue)
        try:
            while True:
                yield await queue.get()
        finally:
            self._subscribers.discard(queue)

    async def _apply_verdict(self, container: str, request_id: str, dest: str, action: str) -> bool:
        """Validate the triple, shell out to ``terok-shield``, emit VerdictApplied.

        Raises [`InvalidAction`][terok_clearance.hub.server.InvalidAction] / [`UnknownRequest`][terok_clearance.hub.server.UnknownRequest] /
        [`VerdictTupleMismatch`][terok_clearance.hub.server.VerdictTupleMismatch] / [`ShieldCliFailed`][terok_clearance.hub.server.ShieldCliFailed] on the
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
        expected_container, expected_dest = live
        if expected_container != container or expected_dest != dest:
            # Put it back — a later legitimate verdict on the same request
            # should still be accepted, so this call's mismatch mustn't
            # consume the entry.
            self._live_verdicts[request_id] = live
            raise VerdictTupleMismatch(
                expected_container=expected_container,
                expected_dest=expected_dest,
                got_container=container,
                got_dest=dest,
            )

        ok, stderr_snippet = await self._verdict_client.apply(container, dest, action)
        if not ok:
            # Restore the authz binding so a retry can reach shield — a
            # spawn / timeout / non-zero exit is transient and the next
            # ``Verdict`` on the same ``request_id`` should still land on
            # the same ``(container, dest)`` pair.
            self._live_verdicts[request_id] = live
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


# ── module-level helpers ───────────────────────────────────────────────


def _translate_reader_event(wire_type: str, raw: dict) -> ClearanceEvent:
    """Build a [`ClearanceEvent`][terok_clearance.ClearanceEvent] from an ingester-parsed dict.

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


def _own_version() -> str:
    """Return our package version for varlink ``GetInfo`` — best-effort."""
    try:
        from importlib.metadata import version

        return version("terok-clearance")
    except Exception:  # pragma: no cover — only hits if metadata is missing
        return "0.0.0"


def _default_reader_socket() -> Path:
    """The EventIngester's default path, re-derived for the hub's wiring."""
    from terok_clearance.hub.ingester import default_socket_path

    return default_socket_path()


# ── stdout bootstrapper (called from _registry._handle_serve) ──────────


async def serve() -> None:  # pragma: no cover — integration path
    """Run the hub service until SIGINT/SIGTERM.

    The entry point ``terok-clearance serve`` hands off here.  Blocks forever
    on a signal-set [`asyncio.Event`][asyncio.Event]; systemd's SIGTERM flips it,
    then [`stop`][terok_clearance.hub.server.ClearanceHub.stop] tears down the server under a timeout.
    """
    from terok_clearance.runtime.service import configure_logging, wait_for_shutdown_signal

    configure_logging()
    hub = ClearanceHub()
    await hub.start()
    try:
        await wait_for_shutdown_signal()
    finally:
        await hub.stop()
