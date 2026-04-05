# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Plain-terminal interactive clearance tool.

Subscribes to Shield1/Clearance1 D-Bus signals and presents blocked
connections in a simple numbered-prompt format.  The operator types
``a <N>`` (allow) or ``d <N>`` (deny) to send verdicts.

No Textual or curses dependency — works over any terminal, SSH, or
serial console.
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys

from terok_dbus._callback import CallbackNotifier, Notification

_log = logging.getLogger(__name__)

_PROTO_NAMES: dict[int, str] = {6: "TCP", 17: "UDP"}


class _TerminalClearance:
    """Interactive terminal loop for shield clearance verdicts."""

    def __init__(self) -> None:
        """Initialise pending state."""
        self._pending: dict[int, Notification] = {}
        self._notifier = CallbackNotifier(on_notify=self._on_notify)
        self._stop: asyncio.Event | None = None

    def _on_notify(self, notification: Notification) -> None:
        """Handle a notification from the EventSubscriber."""
        if notification.replaces_id and notification.replaces_id in self._pending:
            # Verdict applied — remove from pending
            del self._pending[notification.replaces_id]
            color = "\033[32m" if "Allowed" in notification.summary else "\033[31m"
            print(f"{color}{notification.summary}  {notification.body}\033[0m")  # noqa: T201
        elif notification.actions:
            # New blocked connection
            self._pending[notification.nid] = notification
            print(  # noqa: T201
                f"\033[33m[{notification.nid}] BLOCKED  "
                f"{notification.summary}  {notification.body}\033[0m"
            )
        else:
            print(f"{notification.summary}  {notification.body}")  # noqa: T201

    def _show_pending(self) -> None:
        """Print the current pending requests."""
        if not self._pending:
            print("  (no pending requests)")  # noqa: T201
            return
        for nid, n in self._pending.items():
            print(f"  [{nid}] {n.summary}  {n.body}")  # noqa: T201

    def _handle_input(self, line: str) -> None:
        """Parse and dispatch a user command."""
        parts = line.strip().split(None, 1)
        if not parts:
            return
        cmd = parts[0].lower()

        if cmd in ("q", "quit", "exit"):
            if self._stop:
                self._stop.set()
            return

        if cmd in ("l", "list"):
            self._show_pending()
            return

        if cmd in ("h", "help", "?"):
            print(  # noqa: T201
                "Commands:\n"
                "  a <N>   allow request N\n"
                "  d <N>   deny request N\n"
                "  l       list pending\n"
                "  q       quit"
            )
            return

        if cmd not in ("a", "allow", "d", "deny"):
            print(f"Unknown command: {cmd!r} (try 'h' for help)")  # noqa: T201
            return

        if len(parts) < 2:
            print(f"Usage: {cmd} <N>")  # noqa: T201
            return

        try:
            nid = int(parts[1])
        except ValueError:
            print(f"Invalid request number: {parts[1]!r}")  # noqa: T201
            return

        if nid not in self._pending:
            print(f"No pending request [{nid}]")  # noqa: T201
            return

        action = "accept" if cmd in ("a", "allow") else "deny"
        self._notifier.invoke_action(nid, action)

    async def run(self) -> None:
        """Connect to D-Bus and run the interactive loop."""
        from terok_dbus import EventSubscriber

        subscriber = EventSubscriber(self._notifier)
        try:
            await subscriber.start()
        except Exception as exc:
            print(f"D-Bus unavailable: {exc}", file=sys.stderr)  # noqa: T201
            sys.exit(1)

        print("Shield clearance — listening on session bus")  # noqa: T201
        print("Commands: a <N> allow, d <N> deny, l list, q quit\n")  # noqa: T201

        self._stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, self._stop.set)

        # Read stdin in a thread so we don't block the event loop
        reader = asyncio.create_task(self._read_stdin(loop))
        await self._stop.wait()
        reader.cancel()
        await subscriber.stop()
        await self._notifier.disconnect()

    async def _read_stdin(self, loop: asyncio.AbstractEventLoop) -> None:
        """Read lines from stdin in a thread executor."""
        while not self._stop.is_set():
            try:
                line = await loop.run_in_executor(None, sys.stdin.readline)
            except (EOFError, OSError):
                self._stop.set()
                break
            if not line:  # EOF
                self._stop.set()
                break
            self._handle_input(line)


async def run_clearance() -> None:
    """Entry point coroutine for the terminal clearance tool."""
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        level=logging.INFO,
    )
    app = _TerminalClearance()
    await app.run()
