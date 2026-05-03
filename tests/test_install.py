# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``install_service`` — hub + verdict systemd user-unit installer."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from terok_clearance.runtime import installer as _install
from terok_clearance.runtime.installer import (
    HUB_UNIT_NAME,
    NOTIFIER_UNIT_NAME,
    VERDICT_UNIT_NAME,
    check_units_outdated,
    install_notifier_service,
    install_service,
    read_installed_notifier_unit_version,
    read_installed_unit,
    read_installed_unit_version,
)


class TestInstallService:
    """``install_service`` renders both unit templates into the user systemd dir."""

    def test_writes_both_units_with_bin_path_substituted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        with patch.object(_install, "_daemon_reload"):
            hub, verdict = install_service(Path("/usr/local/bin/terok-clearance-hub"))
        assert hub == tmp_path / "systemd" / "user" / HUB_UNIT_NAME
        assert verdict == tmp_path / "systemd" / "user" / VERDICT_UNIT_NAME
        hub_body = hub.read_text()
        verdict_body = verdict.read_text()
        assert "{{BIN}}" not in hub_body
        assert "{{BIN}}" not in verdict_body
        assert "/usr/local/bin/terok-clearance-hub serve" in hub_body
        assert "/usr/local/bin/terok-clearance-hub serve-verdict" in verdict_body

    def test_is_idempotent(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        with patch.object(_install, "_daemon_reload"):
            first = install_service(Path("/a/terok-clearance-hub"))
            second = install_service(Path("/a/terok-clearance-hub"))
        assert first[0].read_text() == second[0].read_text()
        assert first[1].read_text() == second[1].read_text()

    def test_runs_daemon_reload(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        with patch.object(_install, "_daemon_reload") as reload:
            install_service(Path("/a/terok-clearance-hub"))
        reload.assert_called_once()

    def test_daemon_reload_handles_missing_systemctl(self) -> None:
        """systemctl-missing hosts (e.g., CI containers) must not fail the install."""
        with patch.object(_install.shutil, "which", return_value=None):
            _install._daemon_reload()

    def test_default_argv_renders_python_module_invocation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Calling ``install_service()`` bare bakes ``python -m terok_clearance.cli.main``."""
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        with patch.object(_install, "_daemon_reload"):
            hub, verdict = install_service()
        hub_body = hub.read_text()
        verdict_body = verdict.read_text()
        assert "-m terok_clearance.cli.main serve" in hub_body
        assert "-m terok_clearance.cli.main serve-verdict" in verdict_body

    def test_migrates_legacy_terok_dbus_service(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A leftover pre-split ``terok-dbus.service`` is disabled + unlinked."""
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        systemd_dir = tmp_path / "systemd" / "user"
        systemd_dir.mkdir(parents=True)
        legacy = systemd_dir / "terok-dbus.service"
        legacy.write_text("[Unit]\nDescription=pre-split monolith\n")
        with (
            patch.object(_install, "_daemon_reload"),
            patch.object(_install.shutil, "which", return_value="/bin/systemctl"),
            patch.object(_install.subprocess, "run") as run,
        ):
            install_service(Path("/a/terok-clearance-hub"))
        assert not legacy.exists()
        # systemctl was invoked once to disable the legacy unit.
        disable_call = run.call_args_list[0]
        assert "disable" in disable_call.args[0]
        assert "terok-dbus.service" in disable_call.args[0]


class TestRenderExecStart:
    """Each argv token is quoted individually — spaces don't leak across boundaries."""

    def test_single_path_no_spaces_is_unquoted(self) -> None:
        assert (
            _install._render_exec_start(Path("/usr/bin/terok-clearance-hub"))
            == "/usr/bin/terok-clearance-hub"
        )

    def test_single_path_with_spaces_is_quoted(self) -> None:
        rendered = _install._render_exec_start(Path("/home/me/My Tools/terok-clearance-hub"))
        assert rendered == '"/home/me/My Tools/terok-clearance-hub"'

    def test_argv_list_quotes_each_token_individually(self) -> None:
        rendered = _install._render_exec_start(
            [Path("/home/me/My Py/python"), "-m", "terok_clearance.cli.main"]
        )
        assert rendered == '"/home/me/My Py/python" -m terok_clearance.cli.main'

    def test_control_characters_are_refused(self) -> None:
        with pytest.raises(ValueError):
            _install._render_exec_start(Path("/a/terok-clearance-hub\nRestart=never"))


class TestReadInstalledUnit:
    """``read_installed_unit`` returns the hub unit's text, or None when absent."""

    def test_returns_text_when_present(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        with patch.object(_install, "_daemon_reload"):
            install_service(Path("/a/terok-clearance-hub"))
        text = read_installed_unit()
        assert text is not None
        assert "/a/terok-clearance-hub serve" in text

    def test_returns_none_when_absent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        assert read_installed_unit() is None


class TestUnitVersion:
    """Version markers let sickbay tell fresh installs from stale ones."""

    def test_rendered_units_carry_current_version(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        with patch.object(_install, "_daemon_reload"):
            install_service(Path("/a/terok-clearance-hub"))
        assert read_installed_unit_version() == _install._PAIR_UNIT_VERSION
        # Verdict unit carries its own (same version, different marker).
        verdict_text = (tmp_path / "systemd" / "user" / VERDICT_UNIT_NAME).read_text()
        assert f"# terok-clearance-verdict-version: {_install._PAIR_UNIT_VERSION}" in verdict_text

    def test_read_version_returns_none_without_marker(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A hand-written unit without the marker reads as ``None``."""
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        unit_path = tmp_path / "systemd" / "user" / HUB_UNIT_NAME
        unit_path.parent.mkdir(parents=True)
        unit_path.write_text("[Unit]\nDescription=hand-rolled\n[Service]\nExecStart=/x serve\n")
        assert read_installed_unit_version() is None

    def test_notifier_version_reads_independently_of_hub(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Notifier version reader returns ``None`` when only the hub pair is installed.

        Sickbay surfaces both versions side-by-side; the per-unit
        readers must never confuse one install target's drift signal
        with the other.
        """
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        with patch.object(_install, "_daemon_reload"):
            install_service(Path("/a/terok-clearance-hub"))
        assert read_installed_unit_version() == _install._PAIR_UNIT_VERSION
        assert read_installed_notifier_unit_version() is None

    def test_notifier_version_reflects_installed_unit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Once the notifier unit lands on disk its version matches the constant."""
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        with patch.object(_install, "_daemon_reload"):
            install_notifier_service(Path("/a/terok-clearance-notifier"))
        assert read_installed_notifier_unit_version() == _install._NOTIFIER_UNIT_VERSION
        # The notifier unit file is the one that carries this version, not the hub.
        notifier_text = (tmp_path / "systemd" / "user" / NOTIFIER_UNIT_NAME).read_text()
        assert (
            f"# terok-clearance-notifier-version: {_install._NOTIFIER_UNIT_VERSION}"
            in notifier_text
        )

    @pytest.mark.parametrize(
        ("unit_name", "marker_prefix"),
        [
            (HUB_UNIT_NAME, "# terok-clearance-hub-version:"),
            (VERDICT_UNIT_NAME, "# terok-clearance-verdict-version:"),
            (NOTIFIER_UNIT_NAME, "# terok-clearance-notifier-version:"),
        ],
    )
    def test_version_marker_is_on_line_1(self, unit_name: str, marker_prefix: str) -> None:
        """The version marker must be the first line of every shipped template.

        Cross-package convention with terok-sandbox: the line-1 marker is
        the ownership contract that lets sandbox's orphan-sweep glob
        recognise our files without false positives on user-authored
        units that share the name prefix.  Clearance has no orphan-sweep
        of its own today, but adopting the same convention keeps the
        whole terok stack consistent and machine-checks the convention
        against accidental reorderings.
        """
        first_line = _install._read_template(unit_name).splitlines()[0]
        assert first_line.startswith(marker_prefix), (
            f"{unit_name}: expected line 1 to start with {marker_prefix!r}, got {first_line!r}"
        )

    def test_check_outdated_silent_on_fresh_install(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        with patch.object(_install, "_daemon_reload"):
            install_service(Path("/a/terok-clearance-hub"))
        assert check_units_outdated() is None

    def test_check_outdated_silent_when_absent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No unit installed is headless-host shape, not a drift warning."""
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        assert check_units_outdated() is None

    def test_check_outdated_flags_legacy_unit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Pre-split ``terok-dbus.service`` on disk → prompt to rerun setup."""
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        legacy = tmp_path / "systemd" / "user" / "terok-dbus.service"
        legacy.parent.mkdir(parents=True)
        legacy.write_text("[Unit]\nDescription=pre-split monolith\n")
        msg = check_units_outdated()
        assert msg is not None
        assert "terok-dbus.service" in msg
        assert "setup" in msg

    def test_check_outdated_flags_unversioned_unit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        unit_path = tmp_path / "systemd" / "user" / HUB_UNIT_NAME
        unit_path.parent.mkdir(parents=True)
        unit_path.write_text("[Unit]\n[Service]\nExecStart=/x\n")
        msg = check_units_outdated()
        assert msg is not None
        assert "unversioned" in msg
        assert "setup" in msg

    def test_check_outdated_flags_half_installed_pair(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Hub present + verdict missing → stale; operator must rerun setup."""
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        with patch.object(_install, "_daemon_reload"):
            install_service(Path("/a/terok-clearance-hub"))
        (tmp_path / "systemd" / "user" / VERDICT_UNIT_NAME).unlink()
        msg = check_units_outdated()
        assert msg is not None
        assert VERDICT_UNIT_NAME in msg
        assert "setup" in msg


class TestDisableAndUnlink:
    """``_disable_and_unlink`` clears enablement symlinks even without the file."""

    def test_runs_disable_when_unit_file_already_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Dangling ``default.target.wants/`` symlinks survive a manual ``rm``."""
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        with (
            patch.object(_install.shutil, "which", return_value="/bin/systemctl"),
            patch.object(_install.subprocess, "run") as run,
        ):
            _install._disable_and_unlink(HUB_UNIT_NAME)
        assert run.call_count == 1
        assert "disable" in run.call_args.args[0]
        assert HUB_UNIT_NAME in run.call_args.args[0]
