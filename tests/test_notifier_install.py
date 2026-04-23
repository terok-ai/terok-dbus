# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``install_notifier_service`` — desktop-bridge unit installer."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from terok_clearance.runtime import installer as _install
from terok_clearance.runtime.installer import (
    NOTIFIER_UNIT_NAME,
    check_units_outdated,
    install_notifier_service,
    uninstall_notifier_service,
)


class TestInstallNotifierService:
    """``install_notifier_service`` writes the single notifier unit under XDG."""

    def test_writes_unit_with_bin_path_substituted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        with patch.object(_install, "_daemon_reload"):
            dest = install_notifier_service(Path("/usr/local/bin/terok-clearance-notifier"))
        assert dest == tmp_path / "systemd" / "user" / NOTIFIER_UNIT_NAME
        body = dest.read_text()
        assert "{{BIN}}" not in body
        assert "{{UNIT_VERSION}}" not in body
        assert "/usr/local/bin/terok-clearance-notifier" in body
        assert "# terok-clearance-notifier-version:" in body

    def test_accepts_argv_list_fallback_form(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """List form lets pipx-aware callers embed ``python -m`` without shlex-foo."""
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        with patch.object(_install, "_daemon_reload"):
            dest = install_notifier_service(
                ["/usr/bin/python3", "-m", "terok_clearance.notifier.app"]
            )
        body = dest.read_text()
        assert "/usr/bin/python3 -m terok_clearance.notifier.app" in body

    def test_is_idempotent(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        with patch.object(_install, "_daemon_reload"):
            first = install_notifier_service(Path("/a/terok-clearance-notifier"))
            second = install_notifier_service(Path("/a/terok-clearance-notifier"))
        assert first.read_text() == second.read_text()

    def test_runs_daemon_reload(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        with patch.object(_install, "_daemon_reload") as reload:
            install_notifier_service(Path("/a/terok-clearance-notifier"))
        reload.assert_called_once()


class TestUninstallNotifierService:
    """``uninstall_notifier_service`` removes the notifier unit + reloads systemd."""

    def test_unlinks_existing_unit(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        with patch.object(_install, "_daemon_reload"):
            install_notifier_service(Path("/a/terok-clearance-notifier"))
            unit = tmp_path / "systemd" / "user" / NOTIFIER_UNIT_NAME
            assert unit.is_file()
            uninstall_notifier_service()
        assert not unit.is_file()

    def test_runs_daemon_reload(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        with patch.object(_install, "_daemon_reload") as reload:
            uninstall_notifier_service()
        reload.assert_called_once()

    def test_tolerates_missing_unit(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Uninstall on a clean host must not raise — soft-fail every step."""
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        with patch.object(_install, "_daemon_reload"):
            uninstall_notifier_service()  # no assertion needed — just must not raise


class TestCheckUnitsOutdatedCoversNotifier:
    """``check_units_outdated`` reports stale notifier units independently of hub/verdict."""

    def test_current_notifier_reports_ok(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        with patch.object(_install, "_daemon_reload"):
            install_notifier_service(Path("/a/terok-clearance-notifier"))
        assert check_units_outdated() is None

    def test_outdated_notifier_flagged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        unit = tmp_path / "systemd" / "user" / NOTIFIER_UNIT_NAME
        unit.parent.mkdir(parents=True)
        unit.write_text("# terok-clearance-notifier-version: 0\n[Unit]\n")
        warning = check_units_outdated()
        assert warning is not None
        assert NOTIFIER_UNIT_NAME in warning
        assert "outdated" in warning

    def test_unversioned_notifier_flagged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        unit = tmp_path / "systemd" / "user" / NOTIFIER_UNIT_NAME
        unit.parent.mkdir(parents=True)
        unit.write_text("[Unit]\nDescription=legacy\n")
        warning = check_units_outdated()
        assert warning is not None
        assert "unversioned" in warning
