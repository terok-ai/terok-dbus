# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Command registry for terok-dbus.

Provides :class:`CommandDef` and :class:`ArgDef` dataclasses describing
every ``terok-dbus`` subcommand.  The ``COMMANDS`` tuple is the single
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
    """Definition of a terok-dbus subcommand.

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
    from terok_dbus import create_notifier  # tach-ignore

    notifier = await create_notifier()
    try:
        notification_id = await notifier.notify(summary, body, timeout_ms=timeout)
        print(notification_id)  # noqa: T201
    finally:
        await notifier.disconnect()


async def _handle_subscribe() -> None:
    """Run the event subscriber until interrupted."""
    import asyncio
    import logging
    import signal

    from terok_dbus import EventSubscriber, create_notifier  # tach-ignore

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        level=logging.INFO,
    )
    notifier = await create_notifier()
    try:
        subscriber = EventSubscriber(notifier)
        await subscriber.start()
        try:
            stop = asyncio.Event()
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, stop.set)
            await stop.wait()
        finally:
            await subscriber.stop()
    finally:
        await notifier.disconnect()


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
        name="subscribe",
        help="Bridge Shield1/Clearance1 D-Bus signals to desktop notifications",
        handler=_handle_subscribe,
    ),
)
