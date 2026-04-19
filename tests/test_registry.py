# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the terok-dbus command registry."""

from unittest.mock import AsyncMock, patch

import pytest

from terok_dbus._registry import COMMANDS, CommandDef, _handle_notify, _handle_serve


class TestCommandRegistry:
    """Verify command definitions are well-formed."""

    def test_commands_is_tuple(self) -> None:
        assert isinstance(COMMANDS, tuple)

    def test_all_entries_are_commanddef(self) -> None:
        for cmd in COMMANDS:
            assert isinstance(cmd, CommandDef)

    def test_notify_command_exists(self) -> None:
        names = {cmd.name for cmd in COMMANDS}
        assert "notify" in names

    def test_serve_command_exists(self) -> None:
        names = {cmd.name for cmd in COMMANDS}
        assert "serve" in names

    def test_subscribe_is_removed(self) -> None:
        """The old subscribe command was rolled into serve; it must not reappear."""
        names = {cmd.name for cmd in COMMANDS}
        assert "subscribe" not in names

    def test_all_commands_have_handlers(self) -> None:
        for cmd in COMMANDS:
            assert cmd.handler is not None, f"{cmd.name} has no handler"

    def test_notify_has_summary_arg(self) -> None:
        notify = next(cmd for cmd in COMMANDS if cmd.name == "notify")
        arg_names = [a.name for a in notify.args]
        assert "summary" in arg_names

    def test_serve_has_no_required_args(self) -> None:
        serve = next(cmd for cmd in COMMANDS if cmd.name == "serve")
        assert len(serve.args) == 0


class TestHandleNotify:
    """Tests for the ``_handle_notify`` handler function."""

    async def test_sends_notification_and_prints_id(self, capsys: pytest.CaptureFixture) -> None:
        mock_notifier = AsyncMock()
        mock_notifier.notify.return_value = 7

        with patch("terok_dbus.create_notifier", new_callable=AsyncMock) as mock_factory:
            mock_factory.return_value = mock_notifier
            await _handle_notify(summary="Alpha", body="Beta", timeout=5000)

        mock_notifier.notify.assert_awaited_once_with("Alpha", "Beta", timeout_ms=5000)
        mock_notifier.disconnect.assert_awaited_once()
        assert capsys.readouterr().out.strip() == "7"

    async def test_disconnects_on_notify_error(self) -> None:
        mock_notifier = AsyncMock()
        mock_notifier.notify.side_effect = RuntimeError("boom")

        with patch("terok_dbus.create_notifier", new_callable=AsyncMock) as mock_factory:
            mock_factory.return_value = mock_notifier
            with pytest.raises(RuntimeError, match="boom"):
                await _handle_notify(summary="Fail")

        mock_notifier.disconnect.assert_awaited_once()

    async def test_uses_defaults(self) -> None:
        mock_notifier = AsyncMock()
        mock_notifier.notify.return_value = 0

        with patch("terok_dbus.create_notifier", new_callable=AsyncMock) as mock_factory:
            mock_factory.return_value = mock_notifier
            await _handle_notify(summary="Title")

        mock_notifier.notify.assert_awaited_once_with("Title", "", timeout_ms=-1)


class TestHandleServe:
    """The serve handler wires up logging and delegates to ``_serve.serve``."""

    async def test_configures_logging_and_awaits_serve(self) -> None:
        with (
            patch("terok_dbus._serve._configure_logging") as config,
            patch("terok_dbus._serve.serve", new_callable=AsyncMock) as serve,
        ):
            await _handle_serve()
        config.assert_called_once()
        serve.assert_awaited_once()
