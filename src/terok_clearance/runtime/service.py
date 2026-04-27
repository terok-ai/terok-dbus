# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shared helpers for the two long-lived asyncio entry points.

The hub ([`terok_clearance.serve`][terok_clearance.serve]) and the desktop notifier
(``terok-clearance-notifier`` in the ``terok`` package) both need the
same two pieces of systemd-unit plumbing: log to stderr so journald
picks it up, and block on ``SIGINT`` / ``SIGTERM`` until the operator
or systemd tears us down.  Keeping both here means one place to
change if we ever want structured logging or a different shutdown
signal.
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys


def configure_logging(level: int = logging.INFO) -> None:
    """Send INFO-level logs to stderr so journald / systemd pick them up."""
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        level=level,
        stream=sys.stderr,
    )


async def wait_for_shutdown_signal() -> None:  # pragma: no cover — real signals
    """Block the current task until ``SIGINT`` or ``SIGTERM`` arrives."""
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()
