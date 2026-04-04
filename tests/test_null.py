# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for NullNotifier — every method is a silent no-op."""

import pytest

from terok_dbus._null import NullNotifier


@pytest.fixture
def null() -> NullNotifier:
    """A fresh NullNotifier instance."""
    return NullNotifier()


class TestNullNotifier:
    """NullNotifier must accept all calls without side effects."""

    async def test_notify_returns_zero(self, null: NullNotifier):
        assert await null.notify("title") == 0

    async def test_notify_with_body(self, null: NullNotifier):
        assert await null.notify("title", "body") == 0

    async def test_notify_with_actions(self, null: NullNotifier):
        result = await null.notify("t", actions=[("ok", "OK")])
        assert result == 0

    async def test_notify_with_timeout(self, null: NullNotifier):
        assert await null.notify("t", timeout_ms=5000) == 0

    async def test_on_action_is_noop(self, null: NullNotifier):
        await null.on_action(1, lambda _: None)  # should not raise

    async def test_close_is_noop(self, null: NullNotifier):
        await null.close(42)  # should not raise

    async def test_disconnect_is_noop(self, null: NullNotifier):
        await null.disconnect()  # should not raise
