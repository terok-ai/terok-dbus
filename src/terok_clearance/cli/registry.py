# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Command registry for terok-clearance.

Provides :class:`CommandDef` and :class:`ArgDef` dataclasses describing
every ``terok-clearance`` subcommand.  The ``COMMANDS`` tuple is the single
source of truth consumed by both the standalone CLI and the terok
integration layer (``terok dbus …``).

Handler functions are async coroutines accepting ``**kwargs`` that match
the declared :class:`ArgDef` names.
"""

from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ArgDef:
    """Definition of a single CLI argument for a command."""

    name: str
    help: str = ""
    type: Callable[[str], Any] | None = None
    default: Any = None
    action: str | None = None
    dest: str | None = None
    nargs: int | str | None = None


@dataclass(frozen=True)
class CommandDef:
    """Definition of a terok-clearance subcommand.

    Attributes:
        name: Subcommand name (e.g. ``"notify"``).
        help: One-line help string for ``--help``.
        handler: Async callable implementing the command logic.
        args: CLI arguments beyond the subcommand name.
    """

    name: str
    help: str = ""
    handler: Callable[..., Coroutine[Any, Any, None]] | None = None
    args: tuple[ArgDef, ...] = ()


# ── Handler functions ─────────────────────────────────────


async def _handle_notify(*, summary: str, body: str = "", timeout: int = -1) -> None:
    """Send a one-shot desktop notification and print its ID."""
    from terok_clearance.notifications.factory import create_notifier

    notifier = await create_notifier()
    try:
        notification_id = await notifier.notify(summary, body, timeout_ms=timeout)
        print(notification_id)  # noqa: T201
    finally:
        await notifier.disconnect()


async def _handle_serve() -> None:
    """Run the clearance hub service until SIGINT/SIGTERM."""
    from terok_clearance.hub.server import serve

    await serve()


async def _handle_serve_verdict() -> None:
    """Run the verdict-helper service until SIGINT/SIGTERM.

    Separate systemd unit from the hub — the helper execs
    ``terok-shield allow|deny`` (and transitively ``podman unshare``)
    which is incompatible with the seccomp + mount-ns hardening the
    hub unit now carries.
    """
    from terok_clearance.verdict.server import serve

    await serve()


async def _handle_install_service(*, bin_path: str | None = None) -> None:  # NOSONAR S7503
    """Install the terok-clearance systemd user unit and reload the user daemon.

    ``async`` is structural, not semantic: every CommandDef.handler goes
    through ``asyncio.run(handler(**kwargs))`` in ``cli.main``.  Sonar's
    "async without await" rule is correct about the body but the shape
    is required by the dispatcher contract — removing ``async`` breaks
    every other handler's calling convention.
    """
    import shutil
    import sys
    from pathlib import Path as _Path

    from terok_clearance.runtime.installer import install_service

    if bin_path is not None and not bin_path:
        raise SystemExit("install-service: --bin-path cannot be empty")
    discovered = bin_path or shutil.which("terok-clearance-hub")
    resolved: _Path | list[str] = (
        _Path(discovered)
        if discovered is not None
        else [sys.executable, "-m", "terok_clearance.cli.main"]
    )
    dest = install_service(resolved)
    print(f"Installed {dest}")  # noqa: T201
    print(  # noqa: T201
        "Enable with: systemctl --user enable --now terok-dbus"
    )


# ── Clearance handler ────────────────────────────────────


async def _handle_clearance() -> None:
    """Run the interactive terminal clearance tool."""
    from terok_clearance.cli.terminal_clearance import run_clearance

    await run_clearance()


# ── Command definitions ───────────────────────────────────

COMMANDS: tuple[CommandDef, ...] = (
    CommandDef(
        name="notify",
        help="Send a one-shot desktop notification",
        handler=_handle_notify,
        args=(
            ArgDef(name="summary", help="Notification title"),
            ArgDef(name="body", nargs="?", default="", help="Notification body text"),
            ArgDef(
                name="-t/--timeout",
                dest="timeout",
                type=int,
                default=-1,
                help="Expiration timeout in milliseconds (-1 = server default)",
            ),
        ),
    ),
    CommandDef(
        name="serve",
        help="Run the clearance hub (serves org.terok.Clearance1 varlink on a unix socket)",
        handler=_handle_serve,
    ),
    CommandDef(
        name="serve-verdict",
        help="Run the verdict helper (serves org.terok.ClearanceVerdict1 for shield exec)",
        handler=_handle_serve_verdict,
    ),
    CommandDef(
        name="install-service",
        help="Install the terok-clearance systemd user unit (systemctl --user daemon-reload'd)",
        handler=_handle_install_service,
        args=(
            ArgDef(
                name="--bin-path",
                dest="bin_path",
                help="Override the resolved terok-clearance-hub launcher path",
            ),
        ),
    ),
    CommandDef(
        name="clearance",
        help="Interactive terminal tool for shield clearance verdicts",
        handler=_handle_clearance,
    ),
)
