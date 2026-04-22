# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Transport-only varlink client for ``org.terok.Clearance1``.

Connects to the hub over the clearance unix socket, streams events via
a background subscriber task, and exposes ``verdict()`` for the
companion RPC channel.  Doesn't know anything about notification
rendering or desktop state — that's :class:`EventSubscriber`'s job and
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

from terok_dbus._wire import Clearance1Interface, ClearanceEvent, default_clearance_socket_path

_log = logging.getLogger(__name__)

EventCallback = Callable[[ClearanceEvent], Awaitable[None]]


class ClearanceClient:
    """Thin async client for the Clearance1 varlink service.

    Two async coroutines to drive:

    * :meth:`start` — open the subscribe + RPC connections and begin
      relaying events to the user-supplied callback.  Returns once both
      channels are live; events arrive via ``on_event`` from then on.
    * :meth:`verdict` — RPC call; returns ``True`` if ``terok-shield``
      applied the action, ``False`` on any refusal or shield failure.
      The refusal reason is logged at WARNING.

    The callback runs on the same event loop as the rest of the client;
    exceptions it raises are logged and swallowed so one bad handler
    can't kill the stream for every subsequent event.
    """

    def __init__(self, *, socket_path: Path | None = None) -> None:
        """Remember the target socket; defaults to :func:`default_clearance_socket_path`."""
        self._socket_path = socket_path or default_clearance_socket_path()
        self._on_event: EventCallback | None = None
        self._sub_transport: object | None = None
        self._rpc_transport: object | None = None
        self._sub_proxy: object | None = None
        self._rpc_proxy: object | None = None
        self._stream_task: asyncio.Task[None] | None = None
        self._stopping = False

    #: Cap on the reconnect back-off.  Keeps latency-after-hub-restart
    #: bounded for the TUI + notifier while still damping a flapping hub.
    _MAX_RECONNECT_BACKOFF_S = 10.0

    async def start(self, on_event: EventCallback) -> None:
        """Open both connections and begin relaying events to *on_event*.

        The initial connect is awaited synchronously so callers see
        ``start()`` return only after the subscription is live — a
        hub that's down at startup still propagates as an exception.
        Subsequent drops are handled by :meth:`_run_stream`'s internal
        reconnect loop so long-running consumers (TUI, notifier)
        survive a ``systemctl restart terok-dbus`` without
        restarting themselves.
        """
        self._on_event = on_event
        await self._connect()
        self._stream_task = asyncio.create_task(self._run_stream())

    async def _connect(self) -> None:
        """Open both varlink connections and build proxies."""
        self._sub_transport, sub_proto = await connect_unix_varlink(
            VarlinkClientProtocol, str(self._socket_path)
        )
        self._rpc_transport, rpc_proto = await connect_unix_varlink(
            VarlinkClientProtocol, str(self._socket_path)
        )
        self._sub_proxy = sub_proto.make_proxy(Clearance1Interface)
        self._rpc_proxy = rpc_proto.make_proxy(Clearance1Interface)

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

        On ``systemctl restart terok-dbus`` the stream iterator raises
        ``ConnectionResetError`` (or the socket-closed sibling errors);
        sleep with exponential back-off, reopen both transports, and
        resume — TUI / notifier consumers don't have to restart.

        Events that occur during the disconnected window are lost:
        the hub holds no per-subscriber replay buffer.  Snapshot-style
        reconciliation (re-query container state from podman after
        reconnect) belongs to individual consumers.
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
                # Stream ended without raising — treat like a disconnect
                # unless we're being stopped explicitly.
            except asyncio.CancelledError:
                raise
            except (
                ConnectionResetError,
                ConnectionAbortedError,
                BrokenPipeError,
                EOFError,
                OSError,
            ) as exc:
                if self._stopping:
                    return
                _log.info("clearance event stream ended (%s); reconnecting in %.1fs", exc, backoff)
            except Exception:
                if self._stopping:
                    return
                _log.exception("clearance event stream died; reconnecting in %.1fs", backoff)
            if self._stopping:
                return
            self._close_transports()
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, self._MAX_RECONNECT_BACKOFF_S)
            try:
                await self._connect()
                _log.info("clearance client reconnected to hub")
                backoff = 1.0
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — retry any connect failure
                _log.info("hub reconnect failed (%s); retrying", exc)
                # Loop around; the next ``await asyncio.sleep(backoff)`` throttles.

    async def wait_closed(self) -> None:
        """Return when the Subscribe() stream task has ended.

        Lets consumers race the shutdown-signal wait against a hub
        disconnect — :func:`asyncio.wait` picks whichever fires first.
        Swallowing the task's own exception is fine here; ``_run_stream``
        already logged at the right severity.
        """
        if self._stream_task is None:
            return
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await self._stream_task
