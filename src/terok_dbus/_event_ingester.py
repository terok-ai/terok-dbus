# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Unix-socket ingester that relays container events onto the session bus.

Per-container NFLOG readers live in ``NS_ROOTLESS`` (the rootless-podman
user namespace that owns the container netns).  From there, the session
``dbus-daemon``'s ``SO_PEERCRED`` check rejects their connection attempts
— even when ``DBUS_SESSION_BUS_ADDRESS`` points at the right socket.

The hub runs in the host user namespace, so it *can* reach the session
bus.  :class:`EventIngester` gives the readers a pipe to cross: it owns
a unix socket that accepts line-delimited JSON events from any local
connection, decodes them, and calls the matching :class:`ShieldHub`
signal methods on the bus — where emission works.

One socket per hub, one hub per user session.  Readers reconnect on
their own if the hub restarts; the hub tolerates disconnected readers
without logging.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import stat
import struct
from collections.abc import Awaitable, Callable
from pathlib import Path

_log = logging.getLogger(__name__)

_SOCKET_BASENAME = "terok-shield-events.sock"


def default_socket_path() -> Path:
    """Return the canonical ingester path under ``$XDG_RUNTIME_DIR``."""
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if not xdg:
        xdg = f"/run/user/{os.getuid()}"
    return Path(xdg) / _SOCKET_BASENAME


class EventIngester:
    """Accepts JSON event lines from container readers and forwards to the hub.

    Keeps ownership of one AF_UNIX listener and a set of accepted-connection
    handler tasks.  Socket file mode is 0600: only the hub's running user
    can read or write to it, matching the session bus's own ACL model.
    """

    def __init__(
        self,
        *,
        socket_path: Path,
        on_event: Callable[[dict], Awaitable[None]],
    ) -> None:
        """Bind the ingester to a filesystem path and a sink coroutine.

        Args:
            socket_path: Where the listening AF_UNIX socket will live.  The
                path is unlinked first if a stale file exists, so a crashed
                previous run doesn't deadlock startup.
            on_event: Coroutine the ingester awaits once per parsed event.
                Expected to emit the corresponding D-Bus signal; exceptions
                raised here are logged and swallowed so one bad event can't
                tear down the ingester.
        """
        self._socket_path = socket_path
        self._on_event = on_event
        self._server: asyncio.AbstractServer | None = None
        self._clients: set[asyncio.Task] = set()

    async def start(self) -> None:
        """Bind the socket and start accepting connections in the background.

        Hardens the bind in three places: the parent directory is owned by
        the current uid and mode-``0700`` before we touch it; the socket
        itself is created under a ``0177`` umask so it's already mode
        ``0600`` the moment ``bind()`` returns (no TOCTOU window); and we
        ``lstat`` the path afterwards to confirm it's actually a socket —
        a symlink swap between unlink and bind would otherwise let a peer
        redirect our ``os.chmod`` at an arbitrary file.
        """
        self._ensure_private_parent()
        with contextlib.suppress(FileNotFoundError):
            self._socket_path.unlink()
        old_umask = os.umask(0o177)
        try:
            self._server = await asyncio.start_unix_server(
                self._handle_client, path=str(self._socket_path)
            )
        finally:
            os.umask(old_umask)
        lst = os.lstat(self._socket_path)
        if not stat.S_ISSOCK(lst.st_mode):
            raise RuntimeError(f"ingester path is not a socket after bind: {self._socket_path}")
        _log.info("event ingester listening on %s", self._socket_path)

    def _ensure_private_parent(self) -> None:
        """Refuse to bind under a parent dir that isn't owned by us + mode 0700-ish."""
        parent = self._socket_path.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        st = parent.stat()
        if st.st_uid != os.getuid():
            raise RuntimeError(
                f"ingester parent dir not owned by current uid: {parent} (owner uid={st.st_uid})"
            )
        if st.st_mode & 0o077:
            raise RuntimeError(
                f"ingester parent dir is group/world accessible: "
                f"{parent} (mode={oct(st.st_mode & 0o777)})"
            )

    async def stop(self) -> None:
        """Close the server and await any in-flight client tasks."""
        # Cancel client handlers *before* awaiting ``wait_closed()``: from
        # Python 3.12.1 onwards the server tracks active connections and
        # ``wait_closed()`` blocks until every one of them returns.  If we
        # waited first we'd deadlock against our own accepted tasks.
        if self._server is not None:
            self._server.close()
        # Snapshot once: each ``await task`` below yields to the event loop
        # which resumes the handler's ``finally`` and discards itself from
        # ``self._clients``.  Iterating the live set while that happens would
        # raise ``RuntimeError: Set changed size during iteration``.
        pending = tuple(self._clients)
        for task in pending:
            task.cancel()
        for task in pending:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        if self._server is not None:
            await self._server.wait_closed()
            self._server = None
        with contextlib.suppress(FileNotFoundError):
            self._socket_path.unlink()

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Read newline-delimited JSON events until the peer disconnects."""
        task = asyncio.current_task()
        if task is not None:
            self._clients.add(task)
        try:
            if not _peer_uid_matches_ours(writer):
                _log.warning("ingester: rejecting connection from foreign uid")
                return
            while True:
                line = await reader.readline()
                if not line:
                    return
                await self._dispatch(line)
        finally:
            if task is not None:
                self._clients.discard(task)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _dispatch(self, raw: bytes) -> None:
        """Decode one line and forward it to the caller-supplied sink."""
        text = raw.strip()
        if not text:
            return
        try:
            event = json.loads(text)
        except json.JSONDecodeError:
            _log.warning("ingester: dropping malformed JSON: %r", text[:120])
            return
        if not isinstance(event, dict):
            _log.warning("ingester: dropping non-object event: %r", text[:120])
            return
        try:
            await self._on_event(event)
        except Exception as exc:  # noqa: BLE001
            _log.warning("ingester: sink raised %s on %r", exc, event)


# ``struct ucred { pid_t pid; uid_t uid; gid_t gid; }`` on Linux — three
# native ints.  SO_PEERCRED on an AF_UNIX socket returns this as an opaque
# byte buffer that we unpack here.
_UCRED_FORMAT = "3i"
_UCRED_SIZE = struct.calcsize(_UCRED_FORMAT)


def _peer_uid_matches_ours(writer: asyncio.StreamWriter) -> bool:
    """Check via ``SO_PEERCRED`` that the peer runs as our uid.

    The ingester socket lives in ``$XDG_RUNTIME_DIR`` which should already
    be per-user, but a hostile same-uid process (shell, browser, sandbox
    escape) can still connect.  ``SO_PEERCRED`` is the kernel-authenticated
    caller identity — anything else is guessing.
    """
    import socket as _socket

    sock = writer.get_extra_info("socket")
    if sock is None:
        _log.warning("ingester: accepted connection exposes no socket; refusing")
        return False
    try:
        raw = sock.getsockopt(_socket.SOL_SOCKET, _socket.SO_PEERCRED, _UCRED_SIZE)
    except (OSError, AttributeError):
        return False
    _pid, uid, _gid = struct.unpack(_UCRED_FORMAT, raw)
    return uid == os.getuid()
