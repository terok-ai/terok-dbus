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
subcommands (``serve`` vs ``serve-verdict``), so [`install_service`][terok_clearance.runtime.installer.install_service]
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
import sys
from importlib import resources as importlib_resources
from pathlib import Path

#: Default argv for the hub launcher — ``python -m`` the CLI entrypoint.
#:
#: Sandbox used to pass this argv explicitly; baking it in lets
#: callers invoke ``install_service()`` bare.  ``sys.executable``
#: skips PATH resolution (a hostile PATH can't poison the rendered
#: ``ExecStart=``) and lands on the same venv's python that owns the
#: installed clearance package.
_DEFAULT_HUB_ARGV: tuple[str, ...] = (sys.executable, "-m", "terok_clearance.cli.main")

#: Default argv for the notifier launcher — same reasoning as above.
_DEFAULT_NOTIFIER_ARGV: tuple[str, ...] = (sys.executable, "-m", "terok_clearance.notifier.app")

#: Unit files this installer owns.  Each is rendered from a template
#: under ``resources/systemd/``; ``{{UNIT_VERSION}}`` + ``{{BIN}}``
#: substitution happens at render time.
HUB_UNIT_NAME = "terok-clearance-hub.service"
VERDICT_UNIT_NAME = "terok-clearance-verdict.service"
NOTIFIER_UNIT_NAME = "terok-clearance-notifier.service"

#: Name of the pre-split monolithic unit we migrate away from.
_LEGACY_UNIT_NAME = "terok-dbus.service"

#: ``(unit_filename, version_marker_prefix)`` pairs for the hub+verdict
#: pair installed by [`install_service`][terok_clearance.runtime.installer.install_service].  The subcommand
#: (``serve`` vs ``serve-verdict``) is baked into each template's
#: ``ExecStart={{BIN}} <subcommand>`` line, so the installer only
#: substitutes ``{{BIN}}`` + ``{{UNIT_VERSION}}``.
_HUB = (HUB_UNIT_NAME, "# terok-clearance-hub-version:")
_VERDICT = (VERDICT_UNIT_NAME, "# terok-clearance-verdict-version:")
_UNITS = (_HUB, _VERDICT)

#: Version marker pair for the notifier unit, installed separately
#: via [`install_notifier_service`][terok_clearance.runtime.installer.install_notifier_service] because the notifier runs a
#: different launcher (``python -m terok_clearance.notifier.app``)
#: than the hub/verdict pair.
_NOTIFIER = (NOTIFIER_UNIT_NAME, "# terok-clearance-notifier-version:")

_PAIR_UNIT_VERSION = 1
"""Version stamp shared by hub + verdict units (they are installed together).

Bump when either of those two templates changes semantics — e.g.
hardening directives, socket paths, argv shape.  ``_NOTIFIER_UNIT_VERSION``
stays untouched so notifier-only edits don't falsely report hub/verdict
as stale, and vice versa.
"""

_NOTIFIER_UNIT_VERSION = 3
"""Version stamp for the standalone notifier unit.

Kept independent of the hub/verdict pair so each install target can
evolve on its own cadence — the three units ship different ExecStart
shapes, different hardening profiles, and different dependencies on
the session bus.

Version history:
    3 — ``ProtectHome=tmpfs`` + ``BindReadOnlyPaths=%h/.../pipx/...``
        replaced with the simpler ``ProtectHome=read-only``.  On
        Fedora-Atomic-style hosts (``/home`` symlinked to
        ``/var/home``) the tmpfs+bind combo cooperated badly with
        systemd's ``%h`` resolution and the notifier could end up
        with no importable Python at all — silently zero desktop
        popups.  Read-only is threat-equivalent against the
        gnome-shell markup-injection vector that hardening targets
        and works regardless of the venv's actual on-disk path.
    2 — full hub-style hardening profile (ProtectClock,
        Protect{Kernel*,Hostname,Proc}, ProcSubset, PrivateDevices,
        PrivateTmp, PrivateNetwork, ProtectSystem=full, ProtectHome=tmpfs,
        BindReadOnlyPaths for the venv, MemoryDenyWriteExecute,
        SystemCallFilter, RestrictNamespaces).  Identity resolution
        moved to the shield reader (per-event dossier), so the notifier
        no longer forks ``podman inspect`` and can take all the
        namespace/seccomp directives the hub already has.
    1 — initial profile with the directives that don't break podman
        inspect (NoNewPrivileges, LockPersonality, RestrictRealtime,
        RestrictSUIDSGID, SystemCallArchitectures, KeyringMode, UMask,
        IPAddressDeny, RestrictAddressFamilies=AF_UNIX).
"""

# Backwards-compatible alias — the unit name the legacy installer
# exposed as ``UNIT_NAME``.  Kept so out-of-tree tests or tooling that
# reached for it don't silently break; new code should use
# [`HUB_UNIT_NAME`][terok_clearance.runtime.installer.HUB_UNIT_NAME].
UNIT_NAME = HUB_UNIT_NAME


def install_service(bin_path: Path | list[str] | None = None) -> tuple[Path, Path]:
    """Render + write both unit files into the user systemd directory.

    Also disables + unlinks any leftover pre-split ``terok-dbus.service``
    so the operator ends up with exactly the new pair running.  Calls
    ``systemctl --user daemon-reload`` once at the end.

    Args:
        bin_path: ``Path`` to the ``terok-clearance-hub`` launcher, or
            a ``list[str]`` argv.  ``None`` (the default) renders
            ``python -m terok_clearance.cli.main`` against the running
            interpreter — the shape pipx installs use — so callers
            don't need to spell clearance's own module layout.

    Returns:
        ``(hub_path, verdict_path)`` — the on-disk paths of the two
        unit files.
    """
    _uninstall_legacy()
    bin_rendered = _render_exec_start(bin_path if bin_path is not None else list(_DEFAULT_HUB_ARGV))
    dest_dir = _user_systemd_dir()
    dest_dir.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for unit_name, _marker in _UNITS:
        template = _read_template(unit_name)
        rendered = template.replace("{{UNIT_VERSION}}", str(_PAIR_UNIT_VERSION)).replace(
            "{{BIN}}", bin_rendered
        )
        dest = dest_dir / unit_name
        dest.write_text(rendered)
        paths.append(dest)
    _daemon_reload()
    return paths[0], paths[1]


def uninstall_service() -> None:
    """Disable + unlink both new units + any pre-split legacy leftover.

    Symmetric teardown for [`install_service`][terok_clearance.runtime.installer.install_service] — ``terok uninstall``
    calls this instead of rolling its own systemctl + unlink sequence.
    Daemon-reloads once at the end so systemd's in-memory registry
    drops the now-missing units.  All individual steps soft-fail so a
    half-installed tree still ends up clean.
    """
    for name in (HUB_UNIT_NAME, VERDICT_UNIT_NAME, _LEGACY_UNIT_NAME):
        _disable_and_unlink(name)
    _daemon_reload()


def install_notifier_service(bin_path: Path | list[str] | None = None) -> Path:
    """Render + write the notifier unit into the user systemd directory.

    Paired with [`install_service`][terok_clearance.runtime.installer.install_service]: headless hosts that installed
    the hub + verdict pair can opt into the desktop notifier later by
    calling only this function.  Daemon-reloads once at the end.

    Args:
        bin_path: ``Path`` to the notifier launcher, or a ``list[str]``
            argv.  ``None`` (the default) renders
            ``python -m terok_clearance.notifier.app`` against the
            running interpreter — same rationale as [`install_service`][terok_clearance.runtime.installer.install_service].

    Returns:
        The on-disk path of the written unit file.
    """
    bin_rendered = _render_exec_start(
        bin_path if bin_path is not None else list(_DEFAULT_NOTIFIER_ARGV)
    )
    dest_dir = _user_systemd_dir()
    dest_dir.mkdir(parents=True, exist_ok=True)
    template = _read_template(NOTIFIER_UNIT_NAME)
    rendered = template.replace("{{UNIT_VERSION}}", str(_NOTIFIER_UNIT_VERSION)).replace(
        "{{BIN}}", bin_rendered
    )
    dest = dest_dir / NOTIFIER_UNIT_NAME
    dest.write_text(rendered)
    _daemon_reload()
    return dest


def uninstall_notifier_service() -> None:
    """Disable + unlink the notifier unit; daemon-reload once.

    Symmetric teardown for [`install_notifier_service`][terok_clearance.runtime.installer.install_notifier_service].  Soft-fail
    on every step so a half-installed tree still ends up clean.
    """
    _disable_and_unlink(NOTIFIER_UNIT_NAME)
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
    """``systemctl --user disable --now <unit>`` + unlink — soft-fail on every step.

    Always runs ``disable`` even when the unit file is already missing — an
    operator who manually ``rm``'d the file can still have dangling
    ``default.target.wants/`` symlinks that ``disable`` will clear.
    """
    path = _user_systemd_dir() / unit_name
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


#: Phrasing tail appended to every drift message — frontend-agnostic
#: so clearance doesn't have to guess which CLI the operator uses to
#: reinstall (``terok setup``, ``terok-executor setup``, a
#: ``terok-clearance`` verb when one ships).  "your clearance setup
#: command" is vague by design.
_RERUN_HINT = "rerun your clearance setup command"


def check_units_outdated() -> str | None:
    """Return a one-line drift warning if any installed unit is stale, else ``None``.

    Checks hub + verdict together (they're installed as a pair by
    [`install_service`][terok_clearance.runtime.installer.install_service]) plus the notifier independently (headless
    hosts may install it later, or not at all).  ``None`` is returned
    when neither pair nor notifier is installed (headless host, or
    no setup command has run yet); a one-sided hub/verdict pair is
    reported as stale so the operator is prompted to restore it.  A
    legacy ``terok-dbus.service`` on disk counts as "stale" so the
    operator is prompted to rerun setup and get the split pair.
    """
    legacy = _user_systemd_dir() / _LEGACY_UNIT_NAME
    if legacy.is_file():
        return (
            f"{_LEGACY_UNIT_NAME} is from a pre-split release — "
            f"{_RERUN_HINT} to migrate to the hub/verdict pair."
        )
    if (verdict := _check_pair_outdated()) is not None:
        return verdict
    return _check_notifier_outdated()


def _check_pair_outdated() -> str | None:
    """Report stale or half-installed hub+verdict pair, or ``None`` when healthy."""
    present: dict[str, bool] = {}
    for unit_name, marker in _UNITS:
        path = _user_systemd_dir() / unit_name
        if not path.is_file():
            present[unit_name] = False
            continue
        present[unit_name] = True
        if (warning := _drift_warning(unit_name, marker, _PAIR_UNIT_VERSION)) is not None:
            return warning
    if any(present.values()) and not all(present.values()):
        missing = ", ".join(name for name, is_present in present.items() if not is_present)
        return f"half-installed: missing {missing} — {_RERUN_HINT} to restore the hub/verdict pair."
    return None


def _check_notifier_outdated() -> str | None:
    """Report stale notifier unit, or ``None`` when absent or current."""
    unit_name, marker = _NOTIFIER
    path = _user_systemd_dir() / unit_name
    if not path.is_file():
        return None
    return _drift_warning(unit_name, marker, _NOTIFIER_UNIT_VERSION)


def _drift_warning(unit_name: str, marker: str, expected: int) -> str | None:
    """Return a stale-unit warning for *unit_name* vs *expected*, or ``None`` if current."""
    installed = _version_for(unit_name, marker)
    if installed is None or installed < expected:
        installed_label = "unversioned" if installed is None else f"v{installed}"
        return (
            f"{unit_name} is outdated "
            f"(installed {installed_label}, expected v{expected}) — {_RERUN_HINT}."
        )
    return None
