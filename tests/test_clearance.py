# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the terminal clearance tool and its COMMANDS registry entry."""

from __future__ import annotations

import asyncio
from unittest.mock import Mock

from terok_dbus._callback import Notification
from terok_dbus._clearance import _TerminalClearance
from terok_dbus._registry import COMMANDS


def _make_notification(**overrides: object) -> Notification:
    """Build a Notification with sensible defaults."""
    defaults: dict[str, object] = {
        "nid": 1,
        "summary": "Blocked: foo.com:443",
        "body": "Container: c1",
        "actions": [],
        "replaces_id": 0,
        "timeout_ms": 0,
    }
    return Notification(**(defaults | overrides))


class TestOnNotify:
    """Tests for _TerminalClearance._on_notify signal handling."""

    def test_new_blocked_connection(self, capsys) -> None:
        """A notification with actions is added to pending and printed."""
        tc = _TerminalClearance()
        n = _make_notification(actions=[("accept", "Allow")])
        tc._on_notify(n)
        assert 1 in tc._pending
        assert "BLOCKED" in capsys.readouterr().out

    def test_verdict_allowed(self, capsys) -> None:
        """An 'Allowed' replaces_id notification removes from pending."""
        tc = _TerminalClearance()
        tc._pending[1] = _make_notification()
        n = _make_notification(summary="Allowed: foo.com", replaces_id=1, timeout_ms=5000)
        tc._on_notify(n)
        assert 1 not in tc._pending
        out = capsys.readouterr().out
        assert "Allowed" in out
        assert "\033[32m" in out  # green

    def test_verdict_denied(self, capsys) -> None:
        """A 'Denied' replaces_id notification uses red color."""
        tc = _TerminalClearance()
        tc._pending[2] = _make_notification(nid=2)
        n = _make_notification(nid=2, summary="Denied: foo.com", replaces_id=2)
        tc._on_notify(n)
        assert 2 not in tc._pending
        out = capsys.readouterr().out
        assert "Denied" in out
        assert "\033[31m" in out  # red

    def test_informational_notification(self, capsys) -> None:
        """A notification without actions or replaces_id is printed plainly."""
        tc = _TerminalClearance()
        n = _make_notification(summary="Info", body="details")
        tc._on_notify(n)
        assert 1 not in tc._pending
        out = capsys.readouterr().out
        assert "Info" in out
        assert "details" in out

    def test_replaces_unknown_nid_treated_as_informational(self, capsys) -> None:
        """replaces_id pointing to an unknown nid falls through to plain print."""
        tc = _TerminalClearance()
        n = _make_notification(replaces_id=99)
        tc._on_notify(n)
        capsys.readouterr()  # just ensure no crash


class TestHandleInput:
    """Tests for _TerminalClearance._handle_input command parsing."""

    def test_allow(self) -> None:
        """'a <N>' invokes the callback with 'accept'."""
        tc = _TerminalClearance()
        cb = Mock()
        tc._notifier._callbacks[1] = cb
        tc._pending[1] = _make_notification()
        tc._handle_input("a 1")
        cb.assert_called_once_with("accept")

    def test_allow_long_form(self) -> None:
        """'allow <N>' also works."""
        tc = _TerminalClearance()
        cb = Mock()
        tc._notifier._callbacks[1] = cb
        tc._pending[1] = _make_notification()
        tc._handle_input("allow 1")
        cb.assert_called_once_with("accept")

    def test_deny(self) -> None:
        """'d <N>' invokes the callback with 'deny'."""
        tc = _TerminalClearance()
        cb = Mock()
        tc._notifier._callbacks[2] = cb
        tc._pending[2] = _make_notification(nid=2)
        tc._handle_input("d 2")
        cb.assert_called_once_with("deny")

    def test_deny_long_form(self) -> None:
        """'deny <N>' also works."""
        tc = _TerminalClearance()
        cb = Mock()
        tc._notifier._callbacks[2] = cb
        tc._pending[2] = _make_notification(nid=2)
        tc._handle_input("deny 2")
        cb.assert_called_once_with("deny")

    def test_unknown_nid(self, capsys) -> None:
        """Attempting to allow a non-existent request prints an error."""
        tc = _TerminalClearance()
        tc._handle_input("a 99")
        assert "No pending" in capsys.readouterr().out

    def test_missing_nid_argument(self, capsys) -> None:
        """'a' without a number shows usage."""
        tc = _TerminalClearance()
        tc._handle_input("a")
        assert "Usage" in capsys.readouterr().out

    def test_invalid_nid(self, capsys) -> None:
        """Non-numeric request number prints an error."""
        tc = _TerminalClearance()
        tc._handle_input("a abc")
        assert "Invalid" in capsys.readouterr().out

    def test_list(self, capsys) -> None:
        """'l' lists pending requests."""
        tc = _TerminalClearance()
        tc._pending[1] = _make_notification(summary="foo", body="bar")
        tc._handle_input("l")
        out = capsys.readouterr().out
        assert "[1]" in out
        assert "foo" in out

    def test_list_long_form(self, capsys) -> None:
        """'list' also works."""
        tc = _TerminalClearance()
        tc._handle_input("list")
        assert "no pending" in capsys.readouterr().out

    def test_list_empty(self, capsys) -> None:
        """'l' with no pending shows a message."""
        tc = _TerminalClearance()
        tc._handle_input("l")
        assert "no pending" in capsys.readouterr().out

    def test_help(self, capsys) -> None:
        """'h' shows help text."""
        tc = _TerminalClearance()
        tc._handle_input("h")
        out = capsys.readouterr().out
        assert "allow" in out
        assert "deny" in out

    def test_help_question_mark(self, capsys) -> None:
        """'?' also shows help."""
        tc = _TerminalClearance()
        tc._handle_input("?")
        assert "allow" in capsys.readouterr().out

    def test_quit_sets_stop_event(self) -> None:
        """'q' sets the stop event instead of raising."""
        tc = _TerminalClearance()
        tc._stop = asyncio.Event()
        tc._handle_input("q")
        assert tc._stop.is_set()

    def test_quit_without_stop_event(self) -> None:
        """'q' before run() is a no-op (stop is None)."""
        tc = _TerminalClearance()
        tc._handle_input("q")  # should not raise

    def test_exit_sets_stop(self) -> None:
        """'exit' also sets the stop event."""
        tc = _TerminalClearance()
        tc._stop = asyncio.Event()
        tc._handle_input("exit")
        assert tc._stop.is_set()

    def test_empty_input(self) -> None:
        """Empty lines are silently ignored."""
        tc = _TerminalClearance()
        tc._handle_input("")  # should not raise
        tc._handle_input("   ")  # should not raise

    def test_unknown_command(self, capsys) -> None:
        """Unknown commands print an error."""
        tc = _TerminalClearance()
        tc._handle_input("xyz")
        assert "Unknown" in capsys.readouterr().out


class TestClearanceRegistryEntry:
    """The clearance command must be in the COMMANDS registry."""

    def test_clearance_in_commands(self) -> None:
        """COMMANDS includes a 'clearance' entry."""
        names = {cmd.name for cmd in COMMANDS}
        assert "clearance" in names

    def test_clearance_has_handler(self) -> None:
        """The clearance CommandDef has a handler."""
        cmd = next(c for c in COMMANDS if c.name == "clearance")
        assert cmd.handler is not None

    def test_clearance_has_no_args(self) -> None:
        """The clearance command takes no CLI arguments."""
        cmd = next(c for c in COMMANDS if c.name == "clearance")
        assert cmd.args == ()
