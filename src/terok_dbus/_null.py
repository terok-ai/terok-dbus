# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""No-op notifier for headless environments without a D-Bus session bus."""

from collections.abc import Callable, Sequence


class NullNotifier:
    """Silent fallback that satisfies the ``Notifier`` protocol.

    Every method is a no-op. ``notify`` always returns ``0``.
    """

    async def notify(
        self,
        summary: str,
        body: str = "",
        *,
        actions: Sequence[tuple[str, str]] = (),
        timeout_ms: int = -1,
    ) -> int:
        """Accept and discard a notification, returning ``0``."""
        return 0

    async def on_action(
        self,
        notification_id: int,
        callback: Callable[[str], None],
    ) -> None:
        """Accept and discard an action callback registration."""

    async def close(self, notification_id: int) -> None:
        """Accept and discard a close request."""

    async def disconnect(self) -> None:
        """Accept and discard a teardown request."""
