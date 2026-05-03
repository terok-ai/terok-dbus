# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""MAC hardening status probes — SELinux + AppArmor view of clearance assets.

terok-clearance ships optional confined SELinux domains
(``terok_clearance_hub_t``, ``terok_clearance_notifier_t``) and
parallel AppArmor profiles (``terok-clearance-hub``,
``terok-clearance-notifier``).  Both are loaded by the bundled
``install_hardening.sh`` shell script.  This module is the read-side:
status probes consumed by ``terok sickbay`` and ``terok setup`` to
render the per-package hardening row.

Why not import the equivalents from terok-sandbox?  Per the package
architecture (`AGENTS.md`), terok-clearance is a leaf — no
terok-* dependencies of its own.  The probes below are tiny enough
that re-implementing them keeps the dependency graph clean.
"""

from __future__ import annotations

import ctypes
from functools import lru_cache
from importlib.resources import files as _resource_files
from pathlib import Path

CONFINED_DOMAINS: tuple[str, ...] = (
    "terok_clearance_hub_t",
    "terok_clearance_notifier_t",
)
"""SELinux process domains shipped under ``resources/selinux/``.
Verdict daemon is intentionally absent — see the ``.te`` header
comment for why it stays unconfined."""

CONFINED_PROFILES: tuple[str, ...] = (
    "terok-clearance-hub",
    "terok-clearance-notifier",
)
"""AppArmor profile names shipped under ``resources/apparmor/``.
Same scope split as `CONFINED_DOMAINS` — verdict not included."""

_SELINUX_ENFORCE_PATH = Path("/sys/fs/selinux/enforce")
_APPARMOR_SECFS_ROOT = Path("/sys/kernel/security/apparmor")
_APPARMOR_PROFILES_FILE = _APPARMOR_SECFS_ROOT / "profiles"


# ---------- Backend detection ----------


def is_selinux_enabled() -> bool:
    """Return ``True`` if SELinux is active in the running kernel."""
    return _SELINUX_ENFORCE_PATH.is_file()


def is_apparmor_enabled() -> bool:
    """Return ``True`` if AppArmor is active in the running kernel."""
    return _APPARMOR_SECFS_ROOT.is_dir()


# ---------- SELinux domain probes ----------


@lru_cache(maxsize=1)
def _load_libselinux() -> ctypes.CDLL | None:
    """Load ``libselinux.so.1`` for the userspace context-validity probe."""
    try:
        lib = ctypes.CDLL("libselinux.so.1", use_errno=True)
    except OSError:
        return None
    lib.security_check_context.argtypes = [ctypes.c_char_p]
    lib.security_check_context.restype = ctypes.c_int
    return lib


def is_domain_loaded(domain: str) -> bool:
    """Return ``True`` if *domain* is a valid process type in the loaded policy.

    Constructs ``system_u:system_r:<domain>:s0`` and asks the kernel
    via ``security_check_context()``; succeeds iff the type exists
    AND the role association from the module's
    ``role system_r types ...;`` rule is in effect.  The
    role-association requirement is exactly why each ``.te`` carries
    that line — without it the context is invalid even though the
    type exists, and the systemd ``SELinuxContext=`` directive can't
    apply either.
    """
    lib = _load_libselinux()
    if lib is None:
        return False
    ctx = f"system_u:system_r:{domain}:s0".encode()
    return lib.security_check_context(ctx) == 0


def loaded_confined_domains() -> tuple[str, ...]:
    """Return the subset of `CONFINED_DOMAINS` whose modules are loaded.

    Empty tuple → optional hardening layer is not installed.  Full
    tuple → every domain is loaded.  Partial → botched / partial
    install worth surfacing.
    """
    return tuple(d for d in CONFINED_DOMAINS if is_domain_loaded(d))


# ---------- AppArmor profile probes ----------


def _loaded_profiles() -> dict[str, str]:
    """Parse ``/sys/kernel/security/apparmor/profiles`` into ``{name: mode}``.

    World-readable on every distro that ships AppArmor — no privilege
    needed.  Empty on non-AppArmor systems.
    """
    try:
        text = _APPARMOR_PROFILES_FILE.read_text()
    except (FileNotFoundError, PermissionError, OSError):
        return {}
    out: dict[str, str] = {}
    for line in text.splitlines():
        if not line.endswith(")"):
            continue
        head, _, tail = line.rpartition(" (")
        if head:
            out[head.strip()] = tail.rstrip(")").strip()
    return out


def loaded_confined_profiles() -> tuple[str, ...]:
    """Return the subset of `CONFINED_PROFILES` currently loaded."""
    loaded = _loaded_profiles()
    return tuple(p for p in CONFINED_PROFILES if p in loaded)


def profile_modes() -> dict[str, str]:
    """Return ``{profile_name: mode}`` for terok-clearance's profiles only.

    Mode is ``enforce`` / ``complain`` / ``kill`` / ``unconfined``.
    Missing-from-the-dict means the profile isn't loaded.
    """
    loaded = _loaded_profiles()
    return {p: loaded[p] for p in CONFINED_PROFILES if p in loaded}


# ---------- Installer surface ----------


@lru_cache(maxsize=1)
def install_script_path() -> Path:
    """Return the path to the bundled ``install_hardening.sh`` installer.

    Independent of terok-sandbox's installer of the same name; this
    one operates on clearance's own units (hub + notifier).  Both
    scripts are idempotent and can be run in either order; ``terok
    setup`` orchestrates running both when the full stack is
    installed.
    """
    return Path(str(_resource_files("terok_clearance.resources") / "install_hardening.sh"))


def install_command() -> str:
    """Return the full ``sudo bash <path>`` shell command for the installer."""
    return f"sudo bash {install_script_path()}"
