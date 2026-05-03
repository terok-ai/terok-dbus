# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the terok-clearance CLI — subcommand parsing and dispatch."""

from unittest.mock import AsyncMock, patch

import pytest

from terok_clearance.cli.main import _build_parser, main
from terok_clearance.cli.registry import COMMANDS, CommandDef


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


class TestInstallServiceParser:
    """Argument parsing for the ``install-service`` subcommand."""

    def test_parses_with_no_args(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["install-service"])
        assert args.command == "install-service"
        assert args.bin_path is None

    def test_bin_path_flag(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["install-service", "--bin-path", "/opt/terok-clearance"])
        assert args.bin_path == "/opt/terok-clearance"


class TestInstallServiceDispatch:
    """Dispatch tests for ``terok-clearance-hub install-service``."""

    def test_install_service_calls_install(self, tmp_path, monkeypatch) -> None:
        """``install-service`` resolves BIN and writes the units via ``install_service``."""
        hub_path = tmp_path / "terok-clearance-hub.service"
        verdict_path = tmp_path / "terok-clearance-verdict.service"

        def _fake_install(bin_path):
            hub_path.write_text(f"ExecStart={bin_path}\n")
            verdict_path.write_text(f"ExecStart={bin_path}\n")
            return hub_path, verdict_path

        monkeypatch.setattr("terok_clearance.runtime.installer.install_service", _fake_install)
        monkeypatch.setattr("shutil.which", lambda _name: "/opt/terok-clearance")
        with patch("sys.argv", ["terok-clearance", "install-service"]):
            main()
        assert hub_path.read_text().startswith("ExecStart=/opt/terok-clearance")
        assert verdict_path.read_text().startswith("ExecStart=/opt/terok-clearance")

    def test_install_service_respects_explicit_bin_path(self, tmp_path, monkeypatch) -> None:
        seen: dict[str, str] = {}

        def _fake_install(bin_path):
            seen["bin_path"] = str(bin_path)
            return (
                tmp_path / "terok-clearance-hub.service",
                tmp_path / "terok-clearance-verdict.service",
            )

        monkeypatch.setattr("terok_clearance.runtime.installer.install_service", _fake_install)
        with patch("sys.argv", ["terok-clearance", "install-service", "--bin-path", "/custom/bin"]):
            main()
        assert seen["bin_path"] == "/custom/bin"

    def test_install_service_rejects_empty_bin_path(self, monkeypatch) -> None:
        """``--bin-path ''`` is operator error, not "discover it for me"."""

        def _fake_install(bin_path):
            raise AssertionError("install_service must not be called on empty --bin-path")

        monkeypatch.setattr("terok_clearance.runtime.installer.install_service", _fake_install)
        with (
            patch("sys.argv", ["terok-clearance", "install-service", "--bin-path", ""]),
            pytest.raises(SystemExit),
        ):
            main()


class TestNoSubcommand:
    """Bare ``terok-clearance`` with no subcommand."""

    def test_exits_with_code_2(self):
        with patch("sys.argv", ["terok-clearance"]):
            with pytest.raises(SystemExit, match="2"):
                main()


class TestNotifyDispatch:
    """Dispatch tests for ``terok-clearance notify``."""

    def test_notify_sends_notification(self):
        mock_notifier = AsyncMock()
        mock_notifier.notify.return_value = 42

        with (
            patch(
                "terok_clearance.notifications.factory.create_notifier", new_callable=AsyncMock
            ) as mock_factory,
            patch("sys.argv", ["terok-clearance", "notify", "Test", "Body"]),
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
            patch("terok_clearance.cli.main.COMMANDS", mock_commands),
            patch("sys.argv", ["terok-clearance", "notify", "Hi"]),
        ):
            with pytest.raises(SystemExit, match="130"):
                main()


class TestServeDispatch:
    """Dispatch tests for ``terok-clearance serve``."""

    def test_serve_dispatches_to_handler(self) -> None:
        mock_handler = AsyncMock()
        mock_commands = tuple(
            CommandDef(name=cmd.name, handler=mock_handler) if cmd.name == "serve" else cmd
            for cmd in COMMANDS
        )

        with (
            patch("terok_clearance.cli.main.COMMANDS", mock_commands),
            patch("sys.argv", ["terok-clearance", "serve"]),
        ):
            main()
            mock_handler.assert_awaited_once()
