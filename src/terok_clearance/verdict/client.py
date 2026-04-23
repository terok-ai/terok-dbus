# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Hub-side client for the verdict helper.

One method: :meth:`VerdictClient.apply` forwards a pre-validated
``(container, dest, action)`` triple to the helper and returns
``(ok, stderr_snippet)`` — the same shape the inline
``_run_shield`` used to return before the split.  Keeps the hub's
verdict dispatch code identical shape-wise; the only change is that
the shield exec happens in another process with different hardening.

The connection is opened lazily and reused across verdicts so a
flurry of clicks doesn't pay a per-call connect cost.  If the helper
restarts out from under us, the next call reconnects.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from pathlib import Path

from asyncvarlink import VarlinkClientProtocol, connect_unix_varlink

from terok_clearance.verdict.interface import Verdict1Interface
from terok_clearance.verdict.socket import default_verdict_socket_path

_log = logging.getLogger(__name__)


class VerdictClient:
    """Call ``Apply`` on the verdict helper over its unix varlink socket.

    Lazy-connecting: the first :meth:`apply` opens the transport; a
    dropped connection reconnects on the next call.  Safe under
    concurrent verdicts on one instance — asyncvarlink serialises
    per-connection replies anyway, and the reconnect lock keeps two
    callers from racing into the helper socket together.
    """

    def __init__(self, *, socket_path: Path | None = None) -> None:
        """Remember the socket; default to :func:`default_verdict_socket_path`."""
        self._socket_path = socket_path or default_verdict_socket_path()
        self._transport: object | None = None
        self._proxy: object | None = None
        self._connect_lock = asyncio.Lock()

    async def apply(self, container: str, dest: str, action: str) -> tuple[bool, str]:
        """Run one verdict via the helper; return ``(ok, stderr_snippet)``.

        Returns ``(False, reason)`` if the helper is unreachable,
        matching the shape callers used to get from the inline shield
        exec.  Upstream error translation (``ShieldCliFailed``) still
        happens in the hub.
        """
        for attempt in (1, 2):
            try:
                await self._ensure_connected()
                reply = await self._proxy.Apply(
                    container=container,
                    dest=dest,
                    action=action,
                )
                return bool(reply["ok"]), str(reply.get("stderr", ""))
            except (ConnectionResetError, BrokenPipeError, OSError) as exc:
                # One auto-reconnect covers "helper restarted after our
                # last call"; a second failure is genuinely unreachable.
                _log.info("verdict helper unreachable (%s, attempt %d)", exc, attempt)
                await self._disconnect()
                if attempt == 2:
                    return False, f"verdict helper unreachable: {exc}"
        return False, "verdict helper unreachable"

    async def stop(self) -> None:
        """Close the helper connection; no-op when not connected."""
        await self._disconnect()

    async def _ensure_connected(self) -> None:
        """Open the socket + build the proxy if we don't have one already."""
        if self._proxy is not None:
            return
        async with self._connect_lock:
            if self._proxy is not None:
                return
            transport, proto = await connect_unix_varlink(
                VarlinkClientProtocol, str(self._socket_path)
            )
            self._transport = transport
            self._proxy = proto.make_proxy(Verdict1Interface)

    async def _disconnect(self) -> None:
        """Drop the cached transport + proxy; next call reconnects."""
        transport = self._transport
        self._transport = None
        self._proxy = None
        if transport is not None:
            with contextlib.suppress(Exception):
                transport.close()
