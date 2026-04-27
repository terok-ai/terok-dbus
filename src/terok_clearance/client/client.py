# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Transport-only varlink client for ``org.terok.Clearance1``.

Connects to the hub over the clearance unix socket, streams events via
a background subscriber task, and exposes ``verdict()`` for the
companion RPC channel.  Doesn't know anything about notification
rendering or desktop state — that's [`EventSubscriber`][terok_clearance.EventSubscriber]'s job and
lives one module up.

Why two connections: varlink is strictly serial per connection (one
reply-at-a-time, no multiplexing).  A long-lived ``Subscribe(more=true)``
would block every ``Verdict()`` call on the same transport, so we open
one connection for the event stream and a second for the RPC path.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable
from pathlib import Path

from asyncvarlink import VarlinkClientProtocol, connect_unix_varlink
from asyncvarlink.error import VarlinkErrorReply

from terok_clearance.domain.events import ClearanceEvent
from terok_clearance.wire.interface import Clearance1Interface
from terok_clearance.wire.socket import default_clearance_socket_path

_log = logging.getLogger(__name__)

EventCallback = Callable[[ClearanceEvent], Awaitable[None]]


class ClearanceClient:
    """Thin async client for the Clearance1 varlink service.

    Two async coroutines to drive:

    * [`start`][terok_clearance.client.client.ClearanceClient.start] — open the subscribe + RPC connections and begin
      relaying events to the user-supplied callback.  Returns once both
      channels are live; events arrive via ``on_event`` from then on.
    * [`verdict`][terok_clearance.client.client.ClearanceClient.verdict] — RPC call; returns ``True`` if ``terok-shield``
      applied the action, ``False`` on any refusal or shield failure.
      The refusal reason is logged at WARNING.

    The callback runs on the same event loop as the rest of the client;
    exceptions it raises are logged and swallowed so one bad handler
    can't kill the stream for every subsequent event.
    """

    #: Cap on the reconnect back-off.  Keeps latency-after-hub-restart
    #: bounded for the TUI + notifier while still damping a flapping hub.
    _MAX_RECONNECT_BACKOFF_S = 10.0

    #: Socket-closed error classes that should trigger a silent reconnect.
    #: Anything else in the Subscribe() loop is logged as an exception.
    _DISCONNECT_ERRORS = (
        ConnectionResetError,
        ConnectionAbortedError,
        BrokenPipeError,
        EOFError,
        OSError,
    )

    def __init__(self, *, socket_path: Path | None = None) -> None:
        """Remember the target socket; defaults to [`default_clearance_socket_path`][terok_clearance.client.client.default_clearance_socket_path]."""
        self._socket_path = socket_path or default_clearance_socket_path()
        self._on_event: EventCallback | None = None
        self._sub_transport: object | None = None
        self._rpc_transport: object | None = None
        self._sub_proxy: object | None = None
        self._rpc_proxy: object | None = None
        self._stream_task: asyncio.Task[None] | None = None
        self._stopping = False
        # Set by [`poke_reconnect`][terok_clearance.client.client.ClearanceClient.poke_reconnect]; awaited inside the back-off
        # window.  Constructed here (not lazily) so a focus-gain poke
        # that lands between ``start()`` and the first ``_run_stream``
        # iteration isn't silently dropped.
        self._reconnect_poke = asyncio.Event()

    async def start(self, on_event: EventCallback) -> None:
        """Open both connections and begin relaying events to *on_event*.

        The initial connect is awaited synchronously so callers see
        ``start()`` return only after the subscription is live — a
        hub that's down at startup still propagates as an exception.
        Subsequent drops are handled by `_run_stream`'s internal
        reconnect loop so long-running consumers (TUI, notifier)
        survive a ``systemctl restart terok-clearance`` without
        restarting themselves.
        """
        self._on_event = on_event
        self._stopping = False
        await self._connect()
        self._stream_task = asyncio.create_task(self._run_stream())

    async def _connect(self) -> None:
        """Open both varlink connections and build proxies.

        Rolls back the first transport if the second connect (or either
        proxy build) raises, so a partial failure doesn't leak a live
        socket and leave the instance half-open.
        """
        try:
            self._sub_transport, sub_proto = await connect_unix_varlink(
                VarlinkClientProtocol, str(self._socket_path)
            )
            self._rpc_transport, rpc_proto = await connect_unix_varlink(
                VarlinkClientProtocol, str(self._socket_path)
            )
            self._sub_proxy = sub_proto.make_proxy(Clearance1Interface)
            self._rpc_proxy = rpc_proto.make_proxy(Clearance1Interface)
        except BaseException:
            self._close_transports()
            raise

    def _close_transports(self) -> None:
        """Drop both transports + proxies; next I/O forces a reconnect."""
        for t in (self._sub_transport, self._rpc_transport):
            if t is not None:
                with contextlib.suppress(Exception):
                    t.close()
        self._sub_transport = None
        self._rpc_transport = None
        self._sub_proxy = None
        self._rpc_proxy = None

    async def stop(self) -> None:
        """Close both connections and await the stream task."""
        self._stopping = True
        if self._stream_task is not None:
            self._stream_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._stream_task
            self._stream_task = None
        self._close_transports()

    def poke_reconnect(self) -> None:
        """Skip any in-flight reconnect back-off and retry immediately.

        Idempotent; a no-op when the stream is healthy because the
        event is only awaited inside `_run_stream`'s back-off
        window.
        """
        self._reconnect_poke.set()

    async def verdict(self, container: str, request_id: str, dest: str, action: str) -> bool:
        """Apply *action* (``allow`` / ``deny``) to *dest* via the hub's ``Verdict`` RPC.

        Returns ``True`` when the hub accepted and applied the verdict,
        ``False`` for any refusal (unknown request_id, tuple mismatch,
        invalid action, shield-exec failure).  Callers typically ignore
        the return value and let the subsequent ``verdict_applied``
        event drive UI updates; refusal reasons are logged at WARNING.
        """
        if self._rpc_proxy is None:
            _log.error("verdict() called before start()")
            return False
        try:
            reply = await self._rpc_proxy.Verdict(
                container=container,
                request_id=request_id,
                dest=dest,
                action=action,
            )
        except VarlinkErrorReply as err:
            _log.warning(
                "Verdict refused for %s (%s → %s): %s",
                container,
                request_id,
                action,
                err,
            )
            return False
        # reply is {"ok": bool} per the return_parameter wrapper.
        return bool(reply.get("ok", False))

    async def _run_stream(self) -> None:
        """Pump Subscribe() events into the user callback, reconnecting on drop.

        Events that occur during the disconnected window are lost —
        the hub holds no per-subscriber replay buffer, and snapshot-
        style reconciliation (re-query container state on reconnect)
        belongs to individual consumers.
        """
        if self._sub_proxy is None:
            raise RuntimeError("ClearanceClient._run_stream called before connect()")
        backoff = 1.0
        while not self._stopping:
            try:
                async for reply in self._sub_proxy.Subscribe():
                    event = reply["event"]
                    if self._on_event is None:
                        continue
                    try:
                        await self._on_event(event)
                    except Exception:
                        _log.exception("event callback raised for %r", event)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — any drop falls through to reconnect
                if self._stopping:
                    return
                if isinstance(exc, self._DISCONNECT_ERRORS):
                    _log.info(
                        "clearance event stream ended (%s); reconnecting in %.1fs", exc, backoff
                    )
                else:
                    _log.exception("clearance event stream died; reconnecting in %.1fs", backoff)
            if self._stopping:
                return
            self._close_transports()
            try:
                await asyncio.wait_for(self._reconnect_poke.wait(), timeout=backoff)
            except TimeoutError:
                backoff = min(backoff * 2, self._MAX_RECONNECT_BACKOFF_S)
            else:
                self._reconnect_poke.clear()
                backoff = 1.0
            try:
                await self._connect()
                _log.info("clearance client reconnected to hub")
                backoff = 1.0
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — retry any connect failure
                _log.info("hub reconnect failed (%s); retrying", exc)
