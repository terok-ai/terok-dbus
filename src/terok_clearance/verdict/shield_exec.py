# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shell out to ``terok-shield allow|deny`` for a single verdict.

Lives inside the verdict feature because this is the one thing the
verdict helper process exists to do — and it's the one thing the hub
*cannot* do under any real systemd hardening.  ``podman unshare
nsenter nft`` (which shield exec's under the covers) requires the
hub's user+mount namespace to match the pause process's, and any
seccomp-based or mount-ns-isolating unit directive breaks that
setns.  The verdict helper runs unhardened; the hub, freed from
this exec, runs under ``NoNewPrivileges=yes`` + ``@system-service``.

The logic itself is the tuple ``(ok, stderr_snippet)`` that used to
live in ``hub.server.ClearanceHub._run_shield`` — unchanged, just
pulled out so both the hub's inline path (if this ever collapses
back) and the out-of-process helper can reuse it.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import shutil
import sys
from pathlib import Path

_log = logging.getLogger(__name__)

#: Upper bound on a single ``terok-shield allow|deny`` invocation.  Shield
#: holds an nft lock and can also block on a slow podman pause; clients
#: have their own reply timeout, so failing-fast here surfaces the real
#: outcome instead of letting the RPC call hang.
_SHIELD_CLI_TIMEOUT_S = 10.0

#: Cap stderr bytes we forward back to the hub.  Desktop popups can't
#: render multi-kilobyte bodies; clients truncate too.  Prevents a
#: shield crash dump from travelling end-to-end as a varlink error
#: parameter.
_STDERR_CAP_BYTES = 512


async def run_shield(
    shield_binary: str | None, container: str, dest: str, action: str
) -> tuple[bool, str]:
    """Invoke ``terok-shield <action> <container> <dest>``; return ``(ok, snippet)``.

    Bounded by `_SHIELD_CLI_TIMEOUT_S`.  Spawn errors, non-zero
    exit, and timeouts all fold into ``(False, reason)`` so callers
    see one shape regardless of how shield misbehaved.  ``snippet``
    is capped at `_STDERR_CAP_BYTES`.
    """
    if not shield_binary:
        return False, "terok-shield not found on PATH"
    try:
        proc = await asyncio.create_subprocess_exec(
            shield_binary,
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
        _, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=_SHIELD_CLI_TIMEOUT_S)
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


def find_shield_binary() -> str | None:
    """Locate ``terok-shield`` — sibling venv first, then PATH, then ``None``.

    The sibling check handles the pipx / poetry case where terok-shield
    ships in the same venv as terok-clearance; we prefer it over PATH
    so a shell-rc ``PATH`` shim can't redirect verdicts through a
    different installation.  ``is_file`` alone would happily return a
    non-executable artifact, so the exec-bit check prevents a broken
    install from failing every verdict instead of falling through to
    PATH's working copy.
    """
    sibling = Path(sys.executable).parent / "terok-shield"
    if sibling.is_file() and os.access(sibling, os.X_OK):
        return str(sibling)
    return shutil.which("terok-shield")
