# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``install_service`` — systemd user-unit installer."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from terok_dbus import _install
from terok_dbus._install import UNIT_NAME, install_service, read_installed_unit


class TestInstallService:
    """``install_service`` renders the unit template into the user systemd dir."""

    def test_writes_unit_with_bin_path_substituted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        with patch.object(_install, "_daemon_reload"):
            dest = install_service(Path("/usr/local/bin/terok-dbus"))
        assert dest == tmp_path / "systemd" / "user" / UNIT_NAME
        body = dest.read_text()
        assert "{{BIN}}" not in body
        assert "/usr/local/bin/terok-dbus serve" in body

    def test_is_idempotent(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        with patch.object(_install, "_daemon_reload"):
            first = install_service(Path("/a/terok-dbus")).read_text()
            second = install_service(Path("/a/terok-dbus")).read_text()
        assert first == second

    def test_runs_daemon_reload(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        with patch.object(_install, "_daemon_reload") as reload:
            install_service(Path("/a/terok-dbus"))
        reload.assert_called_once()

    def test_daemon_reload_handles_missing_systemctl(self) -> None:
        """systemctl-missing hosts (e.g., CI containers) must not fail the install."""
        with patch.object(_install.shutil, "which", return_value=None):
            _install._daemon_reload()


class TestRenderExecStart:
    """Each argv token is quoted individually — spaces don't leak across boundaries."""

    def test_single_path_no_spaces_is_unquoted(self) -> None:
        assert _install._render_exec_start(Path("/usr/bin/terok-dbus")) == "/usr/bin/terok-dbus"

    def test_single_path_with_spaces_is_quoted(self) -> None:
        rendered = _install._render_exec_start(Path("/home/me/My Tools/terok-dbus"))
        assert rendered == '"/home/me/My Tools/terok-dbus"'

    def test_argv_list_quotes_each_token_individually(self) -> None:
        rendered = _install._render_exec_start(
            [Path("/home/me/My Py/python"), "-m", "terok_dbus._cli"]
        )
        assert rendered == '"/home/me/My Py/python" -m terok_dbus._cli'

    def test_control_characters_are_refused(self) -> None:
        with pytest.raises(ValueError):
            _install._render_exec_start(Path("/a/terok-dbus\nRestart=never"))


class TestReadInstalledUnit:
    """``read_installed_unit`` returns the installed text, or None when absent."""

    def test_returns_text_when_present(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        with patch.object(_install, "_daemon_reload"):
            install_service(Path("/a/terok-dbus"))
        text = read_installed_unit()
        assert text is not None
        assert "/a/terok-dbus serve" in text

    def test_returns_none_when_absent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        assert read_installed_unit() is None
