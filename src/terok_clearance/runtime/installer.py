# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Install the clearance hub + verdict helper systemd user units.

The clearance flow splits across two units:

* ``terok-clearance-hub.service`` — varlink server, subscriber
  fan-out, authz binding.  Hardened (NNP + seccomp + mount-ns
  isolation).
* ``terok-clearance-verdict.service`` — stateless helper, execs
  ``terok-shield allow|deny``.  Unhardened (podman setns requires
  it).

Both run the same ``terok-clearance-hub`` launcher with different
subcommands (``serve`` vs ``serve-verdict``), so :func:`install_service`
takes one ``bin_path`` and writes both units.

Legacy migration: earlier releases shipped one monolithic
``terok-dbus.service``.  On first post-split install the legacy unit
is disabled + unlinked before the new pair goes down, so operators
don't end up running two hubs against the same socket.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess  # nosec B404
from importlib import resources as importlib_resources
from pathlib import Path

#: Unit files this installer owns.  Both are rendered from templates
#: that live under ``resources/systemd/``; ``{{UNIT_VERSION}}`` +
#: ``{{BIN}}`` substitution happens at render time.
HUB_UNIT_NAME = "terok-clearance-hub.service"
VERDICT_UNIT_NAME = "terok-clearance-verdict.service"

#: Name of the pre-split monolithic unit we migrate away from.
_LEGACY_UNIT_NAME = "terok-dbus.service"

#: ``(unit_filename, version_marker_prefix)`` pairs.  The subcommand
#: (``serve`` vs ``serve-verdict``) is baked into each template's
#: ``ExecStart={{BIN}} <subcommand>`` line, so the installer only
#: substitutes ``{{BIN}}`` + ``{{UNIT_VERSION}}``.
_HUB = (HUB_UNIT_NAME, "# terok-clearance-hub-version:")
_VERDICT = (VERDICT_UNIT_NAME, "# terok-clearance-verdict-version:")
_UNITS = (_HUB, _VERDICT)

_UNIT_VERSION = 1
"""Bump when either unit template's semantics change.

The marker is rendered into each unit at install time so
:func:`check_units_outdated` can tell a current install from an older
generation — any installed unit without a marker (the pre-split
monolithic ``terok-dbus.service``) reads as ``None`` and is surfaced
as stale.
"""

# Backwards-compatible alias — the unit name the legacy installer
# exposed as ``UNIT_NAME``.  Kept so out-of-tree tests or tooling that
# reached for it don't silently break; new code should use
# :data:`HUB_UNIT_NAME`.
UNIT_NAME = HUB_UNIT_NAME


def install_service(bin_path: Path | list[str]) -> tuple[Path, Path]:
    """Render + write both unit files into the user systemd directory.

    Also disables + unlinks any leftover pre-split ``terok-dbus.service``
    so the operator ends up with exactly the new pair running.  Calls
    ``systemctl --user daemon-reload`` once at the end.

    Args:
        bin_path: ``Path`` to the ``terok-clearance-hub`` launcher, or
            a ``list[str]`` argv (the module-fallback form, e.g.
            ``[sys.executable, "-m", "terok_clearance.cli.main"]``).

    Returns:
        ``(hub_path, verdict_path)`` — the on-disk paths of the two
        unit files.
    """
    _uninstall_legacy()
    bin_rendered = _render_exec_start(bin_path)
    dest_dir = _user_systemd_dir()
    dest_dir.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for unit_name, _marker in _UNITS:
        template = _read_template(unit_name)
        rendered = template.replace("{{UNIT_VERSION}}", str(_UNIT_VERSION)).replace(
            "{{BIN}}", bin_rendered
        )
        dest = dest_dir / unit_name
        dest.write_text(rendered)
        paths.append(dest)
    _daemon_reload()
    return paths[0], paths[1]


def uninstall_service() -> None:
    """Disable + unlink both new units + any pre-split legacy leftover.

    Symmetric teardown for :func:`install_service` — ``terok uninstall``
    calls this instead of rolling its own systemctl + unlink sequence.
    Daemon-reloads once at the end so systemd's in-memory registry
    drops the now-missing units.  All individual steps soft-fail so a
    half-installed tree still ends up clean.
    """
    for name in (HUB_UNIT_NAME, VERDICT_UNIT_NAME, _LEGACY_UNIT_NAME):
        _disable_and_unlink(name)
    _daemon_reload()


def _uninstall_legacy() -> None:
    """Disable + unlink the pre-split monolithic unit if it's installed.

    Runs before the new units land so a user with an existing
    ``terok-dbus.service`` doesn't end up with two long-running hubs
    racing for the same varlink socket.  Silent when systemctl is
    absent (CI containers) or the legacy unit isn't there.
    """
    _disable_and_unlink(_LEGACY_UNIT_NAME)


def _disable_and_unlink(unit_name: str) -> None:
    """``systemctl --user disable --now <unit>`` + unlink — soft-fail on every step."""
    path = _user_systemd_dir() / unit_name
    if not path.is_file():
        return
    systemctl = shutil.which("systemctl")
    if systemctl:
        with contextlib.suppress(Exception):
            subprocess.run(  # nosec B603
                [systemctl, "--user", "disable", "--now", unit_name],
                check=False,
                capture_output=True,
            )
    with contextlib.suppress(OSError):
        path.unlink()


def _render_exec_start(bin_path: Path | list[str]) -> str:
    """Prepare a ``{{BIN}}`` substitution value suitable for ``ExecStart=``.

    Quotes each argv token individually — spaces inside a single element
    (an install path under ``/home/me/My Tools/``) stay inside one
    token, and whitespace between tokens remains a systemd separator.
    Rejects control characters that would break line semantics in the
    rendered unit.
    """
    tokens = [str(bin_path)] if isinstance(bin_path, Path) else [str(t) for t in bin_path]
    for token in tokens:
        if any(ch in token for ch in ("\n", "\r")):
            raise ValueError(f"bin_path token is not safe to embed in ExecStart=: {token!r}")
    return " ".join(_quote_exec_token(t) for t in tokens)


def _quote_exec_token(token: str) -> str:
    """Wrap *token* in systemd double-quotes when it contains tokeniser-meaningful whitespace."""
    if any(ch.isspace() for ch in token):
        return f'"{_systemd_quote(token)}"'
    return _systemd_quote(token)


def _systemd_quote(value: str) -> str:
    """Escape ``"`` and ``\\`` so *value* can live safely inside a quoted string."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _read_template(unit_name: str) -> str:
    """Load the named unit template from the package's ``resources/systemd``."""
    source = (
        importlib_resources.files("terok_clearance")
        .joinpath("resources")
        .joinpath("systemd")
        .joinpath(unit_name)
    )
    return source.read_text()


def _user_systemd_dir() -> Path:
    """Resolve ``$XDG_CONFIG_HOME/systemd/user`` (default ``~/.config/systemd/user``)."""
    xdg_config = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg_config) if xdg_config else Path.home() / ".config"
    return base / "systemd" / "user"


def _daemon_reload() -> None:
    """Ask the user's systemd to re-read its unit files; silently skip if unavailable."""
    systemctl = shutil.which("systemctl")
    if not systemctl:
        return
    subprocess.run(  # nosec B603
        [systemctl, "--user", "daemon-reload"],
        check=False,
        capture_output=True,
    )


def read_installed_unit() -> str | None:
    """Return the hub unit's file contents, or ``None`` if absent.

    Kept for backwards compatibility with out-of-tree callers that
    grew used to the pre-split single-unit API — reads the hub unit
    (the one that was formerly ``terok-dbus.service``).
    """
    path = _user_systemd_dir() / HUB_UNIT_NAME
    try:
        return path.read_text()
    except OSError:
        return None


def read_installed_unit_version() -> int | None:
    """Return the hub unit's ``# terok-clearance-hub-version:`` stamp, or ``None``.

    ``None`` is either "unit not installed" or "unit installed without
    a marker" (the pre-split legacy unit) — ``check_units_outdated``
    differentiates between those in its operator-facing message.
    """
    return _version_for(HUB_UNIT_NAME, _HUB[1])


def _version_for(unit_name: str, marker_prefix: str) -> int | None:
    """Return the version stamp from a specific installed unit, or ``None``."""
    path = _user_systemd_dir() / unit_name
    try:
        text = path.read_text()
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith(marker_prefix):
            try:
                return int(line.split(":", 1)[1].strip())
            except ValueError:
                return None
    return None


def check_units_outdated() -> str | None:
    """Return a one-line drift warning if any installed unit is stale, else ``None``.

    Checks both the hub and the verdict units.  ``None`` is returned
    when neither is installed (headless host, or ``terok setup``
    hasn't run yet).  A legacy ``terok-dbus.service`` on disk counts
    as "stale" so the operator is prompted to rerun setup and get
    the split pair.
    """
    legacy = _user_systemd_dir() / _LEGACY_UNIT_NAME
    if legacy.is_file():
        return (
            f"{_LEGACY_UNIT_NAME} is from a pre-split release — "
            "rerun `terok setup` to migrate to the hub/verdict pair."
        )
    for unit_name, marker in _UNITS:
        path = _user_systemd_dir() / unit_name
        if not path.is_file():
            continue
        installed = _version_for(unit_name, marker)
        if installed is None or installed < _UNIT_VERSION:
            installed_label = "unversioned" if installed is None else f"v{installed}"
            return (
                f"{unit_name} is outdated "
                f"(installed {installed_label}, expected v{_UNIT_VERSION}) — rerun `terok setup`."
            )
    return None
