# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the terok-dbus command registry."""

from terok_dbus._registry import COMMANDS, CommandDef


class TestCommandRegistry:
    """Verify command definitions are well-formed."""

    def test_commands_is_tuple(self):
        assert isinstance(COMMANDS, tuple)

    def test_all_entries_are_commanddef(self):
        for cmd in COMMANDS:
            assert isinstance(cmd, CommandDef)

    def test_notify_command_exists(self):
        names = {cmd.name for cmd in COMMANDS}
        assert "notify" in names

    def test_subscribe_command_exists(self):
        names = {cmd.name for cmd in COMMANDS}
        assert "subscribe" in names

    def test_all_commands_have_handlers(self):
        for cmd in COMMANDS:
            assert cmd.handler is not None, f"{cmd.name} has no handler"

    def test_notify_has_summary_arg(self):
        notify = next(cmd for cmd in COMMANDS if cmd.name == "notify")
        arg_names = [a.name for a in notify.args]
        assert "summary" in arg_names

    def test_subscribe_has_no_required_args(self):
        subscribe = next(cmd for cmd in COMMANDS if cmd.name == "subscribe")
        assert len(subscribe.args) == 0
