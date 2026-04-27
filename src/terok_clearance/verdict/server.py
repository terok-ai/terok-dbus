# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""The verdict helper — a minimal varlink server wrapping ``terok-shield``.

One process, one socket, one method (``Apply``).  Runs as its own
systemd user unit (``terok-clearance-verdict.service``) so the
companion hub unit can take full seccomp + mount-ns hardening without
tripping the kernel's NNP requirement and SELinux's denial of the
``unconfined_t → container_runtime_t`` transition that rootless podman
needs every time shield exec's ``podman unshare nsenter nft``.

Stateless: no authz decisions, no request-id binding, no fan-out.
The hub already validated the verdict triple before forwarding; the
helper exists solely to isolate the hostile exec path from the
hardened receive path.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from pathlib import Path

from asyncvarlink import VarlinkInterfaceRegistry, create_unix_server
from asyncvarlink.serviceinterface import VarlinkServiceInterface

from terok_clearance.verdict.interface import Verdict1Interface
from terok_clearance.verdict.shield_exec import find_shield_binary, run_shield
from terok_clearance.verdict.socket import default_verdict_socket_path
from terok_clearance.wire.socket import bind_hardened

_log = logging.getLogger(__name__)


class VerdictServer:
    """Per-process wrapper around the ``Apply`` varlink interface.

    The hub is the only legitimate client; ``SO_PEERCRED`` on the unix
    socket rejects peers with a different UID, and
    [`bind_hardened`][terok_clearance.wire.socket.bind_hardened] leaves the
    socket mode ``0600`` for the lifetime of the server.
    """

    def __init__(
        self,
        *,
        socket_path: Path | None = None,
        shield_binary: str | None = None,
    ) -> None:
        """Configure the socket + shield executable path."""
        self._socket_path = socket_path or default_verdict_socket_path()
        self._shield_binary = shield_binary or find_shield_binary()
        self._server: object | None = None

    async def start(self) -> None:
        """Bind the varlink server and start accepting hub verdict calls."""
        registry = VarlinkInterfaceRegistry()
        registry.register_interface(Verdict1Interface(apply_verdict=self._apply))
        registry.register_interface(
            VarlinkServiceInterface(
                vendor="terok",
                product="terok-clearance-verdict",
                version=_own_version(),
                url="https://github.com/terok-ai/terok-clearance",
                registry=registry,
            )
        )

        async def _factory(path: str) -> object:
            return await create_unix_server(registry.protocol_factory, path=path)

        self._server = await bind_hardened(_factory, self._socket_path, "verdict")
        _log.info("verdict helper online at %s", self._socket_path)

    async def stop(self) -> None:
        """Close the varlink server; existing in-flight Apply calls finish first."""
        if self._server is None:
            return
        self._server.close()
        with contextlib.suppress(AttributeError):
            self._server.close_clients()
        with contextlib.suppress(TimeoutError, Exception):
            await asyncio.wait_for(self._server.wait_closed(), timeout=1.0)
        self._server = None

    async def _apply(self, container: str, dest: str, action: str) -> tuple[bool, str]:
        """Forward one verdict to [`run_shield`][terok_clearance.verdict.server.run_shield], no validation."""
        return await run_shield(self._shield_binary, container, dest, action)


async def serve() -> None:
    """Bring the verdict helper online and stay up until SIGINT/SIGTERM.

    Mirrors [`terok_clearance.hub.server.serve`][terok_clearance.hub.server.serve] so the CLI layer
    can dispatch both entrypoints through the same ``asyncio.run``
    pattern.
    """
    from terok_clearance.runtime.service import configure_logging, wait_for_shutdown_signal

    configure_logging()
    server = VerdictServer()
    await server.start()
    try:
        await wait_for_shutdown_signal()
    finally:
        await server.stop()


def _own_version() -> str:
    """Return the package version for varlink ``GetInfo`` — best-effort."""
    try:
        from importlib.metadata import version

        return version("terok-clearance")
    except Exception:  # pragma: no cover — only hits if metadata is missing
        return "0.0.0"
