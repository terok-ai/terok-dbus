# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Install the terok-dbus systemd user unit and reload the user daemon.

Renders the bundled ``terok-dbus.service`` into
``$XDG_CONFIG_HOME/systemd/user/terok-dbus.service`` with ``{{BIN}}``
replaced by the operator-resolved ``terok-dbus`` invocation, and
optionally bakes in ``TEROK_SHIELD_STATE_DIR`` so the hub sees the
same shield state root as the interactive shell at install time.
Matches the install patterns used by ``terok-credential-proxy`` and
``terok-gate``.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404
from importlib import resources as importlib_resources
from pathlib import Path

UNIT_NAME = "terok-dbus.service"
STATE_DIR_ENV = "TEROK_SHIELD_STATE_DIR"


def install_service(bin_path: Path | list[str]) -> Path:
    """Render the unit template, write it into the user systemd directory, reload.

    Captures ``TEROK_SHIELD_STATE_DIR`` from the current environment
    (typically the interactive shell's) and bakes it into the generated
    unit as an ``Environment=`` directive so the hub's shelled-out
    ``terok-shield`` CLI resolves the same state root.  When the env
    var is unset, no ``Environment=`` line is added and shield's CLI
    uses its XDG-based default (which is usually the right answer).

    Args:
        bin_path: Either a ``Path`` naming the ``terok-dbus`` launcher
            (a single executable, space-tolerant — e.g. from
            ``shutil.which("terok-dbus")``) or a ``list[str]`` argv
            (the module-fallback form, e.g.
            ``[sys.executable, "-m", "terok_dbus._cli"]``).  Each token
            is quoted individually on render so systemd's whitespace
            tokeniser sees the intended argv boundaries regardless of
            spaces inside any element.

    Returns:
        The on-disk path the unit was written to.
    """
    template = _read_template()
    rendered = template.replace("{{BIN}}", _render_exec_start(bin_path))
    rendered = _inject_state_dir_env(rendered, os.environ.get(STATE_DIR_ENV))
    dest = _user_systemd_dir() / UNIT_NAME
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(rendered)
    _daemon_reload()
    return dest


def _inject_state_dir_env(rendered: str, state_dir: str | None) -> str:
    """Add an ``Environment=TEROK_SHIELD_STATE_DIR=...`` line when the env was set.

    The line goes into the ``[Service]`` block immediately after
    ``ExecStart=``; keeps the unit readable as a narrative (what it runs,
    then what env it runs with).  A leading marker comment makes the
    mismatch-check in sickbay auditable at a glance.
    """
    if not state_dir:
        return rendered
    if any(ch in state_dir for ch in ("\n", "\r")):
        raise ValueError(f"{STATE_DIR_ENV} is not safe to embed in Environment=: {state_dir!r}")
    quoted = _systemd_quote(state_dir)
    marker = f"# injected-at-install: {STATE_DIR_ENV}={state_dir}\n"
    env_line = f'Environment="{STATE_DIR_ENV}={quoted}"\n'
    lines = rendered.splitlines(keepends=True)
    result: list[str] = []
    injected = False
    for line in lines:
        result.append(line)
        if not injected and line.startswith("ExecStart="):
            result.append(marker)
            result.append(env_line)
            injected = True
    return "".join(result)


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


def _read_template() -> str:
    """Load the unit template from the installed package's ``resources/systemd``."""
    source = (
        importlib_resources.files("terok_dbus")
        .joinpath("resources")
        .joinpath("systemd")
        .joinpath(UNIT_NAME)
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
    """Return the contents of the installed hub unit, or ``None`` if absent.

    Used by sickbay to diagnose configuration drift against the current
    shell's ``TEROK_SHIELD_STATE_DIR`` setting.
    """
    path = _user_systemd_dir() / UNIT_NAME
    try:
        return path.read_text()
    except OSError:
        return None


def extract_baked_state_dir(unit_text: str) -> str | None:
    """Pull the baked ``TEROK_SHIELD_STATE_DIR`` out of an installed unit's text.

    Handles both the plain ``Environment=VAR=value`` and the
    ``Environment="VAR=value with spaces"`` forms the installer may emit.
    Returns ``None`` when no matching line is present.
    """
    for line in unit_text.splitlines():
        stripped = line.strip()
        for prefix in (
            f'Environment="{STATE_DIR_ENV}=',
            f"Environment={STATE_DIR_ENV}=",
        ):
            if stripped.startswith(prefix):
                value = stripped[len(prefix) :]
                if prefix.endswith('"'):
                    pass  # prefix already consumed the opening quote
                if value.endswith('"'):
                    value = value[:-1]
                return value.replace('\\"', '"').replace("\\\\", "\\")
    return None
