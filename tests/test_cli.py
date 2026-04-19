# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the terok-dbus CLI — subcommand parsing and dispatch."""

from unittest.mock import AsyncMock, patch

import pytest

from terok_dbus._cli import _build_parser, main
from terok_dbus._registry import COMMANDS, CommandDef


class TestNotifyParser:
    """Argument parsing for the ``notify`` subcommand."""

    def test_summary_required(self):
        parser = _build_parser()
        args = parser.parse_args(["notify", "Hello"])
        assert args.command == "notify"
        assert args.summary == "Hello"
        assert args.body == ""
        assert args.timeout == -1

    def test_summary_and_body(self):
        parser = _build_parser()
        args = parser.parse_args(["notify", "Hello", "World"])
        assert args.summary == "Hello"
        assert args.body == "World"

    def test_timeout_flag(self):
        parser = _build_parser()
        args = parser.parse_args(["notify", "-t", "5000", "Hello"])
        assert args.timeout == 5000

    def test_timeout_long_flag(self):
        parser = _build_parser()
        args = parser.parse_args(["notify", "--timeout", "3000", "Hello"])
        assert args.timeout == 3000


class TestServeParser:
    """Argument parsing for the ``serve`` subcommand."""

    def test_parses_with_no_args(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["serve"])
        assert args.command == "serve"


class TestNoSubcommand:
    """Bare ``terok-dbus`` with no subcommand."""

    def test_exits_with_code_2(self):
        with patch("sys.argv", ["terok-dbus"]):
            with pytest.raises(SystemExit, match="2"):
                main()


class TestNotifyDispatch:
    """Dispatch tests for ``terok-dbus notify``."""

    def test_notify_sends_notification(self):
        mock_notifier = AsyncMock()
        mock_notifier.notify.return_value = 42

        with (
            patch("terok_dbus.create_notifier", new_callable=AsyncMock) as mock_factory,
            patch("sys.argv", ["terok-dbus", "notify", "Test", "Body"]),
        ):
            mock_factory.return_value = mock_notifier
            main()
            mock_notifier.notify.assert_awaited_once_with("Test", "Body", timeout_ms=-1)
            mock_notifier.disconnect.assert_awaited_once()


class TestKeyboardInterrupt:
    """Handler raises KeyboardInterrupt → exit code 130."""

    def test_keyboard_interrupt_exits_130(self):
        mock_handler = AsyncMock(side_effect=KeyboardInterrupt)
        mock_commands = tuple(
            CommandDef(name=cmd.name, handler=mock_handler, args=cmd.args)
            if cmd.name == "notify"
            else cmd
            for cmd in COMMANDS
        )

        with (
            patch("terok_dbus._cli.COMMANDS", mock_commands),
            patch("sys.argv", ["terok-dbus", "notify", "Hi"]),
        ):
            with pytest.raises(SystemExit, match="130"):
                main()


class TestServeDispatch:
    """Dispatch tests for ``terok-dbus serve``."""

    def test_serve_dispatches_to_handler(self) -> None:
        mock_handler = AsyncMock()
        mock_commands = tuple(
            CommandDef(name=cmd.name, handler=mock_handler) if cmd.name == "serve" else cmd
            for cmd in COMMANDS
        )

        with (
            patch("terok_dbus._cli.COMMANDS", mock_commands),
            patch("sys.argv", ["terok-dbus", "serve"]),
        ):
            main()
            mock_handler.assert_awaited_once()
