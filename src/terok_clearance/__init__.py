# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Clearance hub + desktop notification library for terok.

The operator-UI plane for terok-shield: turns shield's blocked-
connection events into Allow/Deny prompts and routes the operator's
verdict back to shield for enforcement.  Two axes of pluggability
apply:

* **Producer (event source) — closed.**  Shield is the only
  producer.  The wire vocabulary (``shield_up``, ``connection_blocked``,
  …) names shield's state machine, and the verdict path execs
  ``terok-shield allow|deny``.  A non-shield "clearance" wouldn't
  work end-to-end; the package is shield's UI plane, not a generic
  firewall console.
* **Operator UI (consumer) — open.**  Anything that subscribes to
  the hub's varlink stream and implements the
  [`Notifier`][terok_clearance.Notifier] protocol on the verdict-routing side
  is a valid UI: today the D-Bus desktop notifier
  ([`DbusNotifier`][terok_clearance.DbusNotifier]), the standalone Textual
  ``terok clearance`` app, and the embedded ``terok-tui`` screen all
  ride on this seam.

Container-runtime inspection is no longer a clearance concern: the
shield reader resolves the orchestrator-supplied dossier at emit
time and ships it on the wire (``ClearanceEvent.dossier``), so
clearance has no Python-level coupling to any runtime.

Two unrelated wire formats live under this one package as a result:

* ``org.terok.Clearance1`` over a unix-socket **varlink** transport —
  the hub ([`ClearanceHub`][terok_clearance.ClearanceHub]) and the client library
  ([`ClearanceClient`][terok_clearance.ClearanceClient], [`EventSubscriber`][terok_clearance.EventSubscriber]) that drive the
  per-container block / verdict / lifecycle flow.
* ``org.freedesktop.Notifications`` over **D-Bus** — the
  [`DbusNotifier`][terok_clearance.DbusNotifier] wrapper that renders those events as desktop
  popups.  Kept because that's the OS API; every other D-Bus path in
  this package (``org.terok.Shield1``) was removed in favour of the
  varlink transport.
"""

from terok_clearance.client.client import ClearanceClient
from terok_clearance.client.subscriber import EventSubscriber
from terok_clearance.domain.events import ClearanceEvent
from terok_clearance.hub.server import ClearanceHub, serve
from terok_clearance.notifications.callback import CallbackNotifier, Notification
from terok_clearance.notifications.desktop import DbusNotifier
from terok_clearance.notifications.factory import create_notifier
from terok_clearance.notifications.null import NullNotifier
from terok_clearance.notifications.protocol import Notifier
from terok_clearance.runtime.hardening import (
    CONFINED_DOMAINS as HARDENING_CONFINED_DOMAINS,
    CONFINED_PROFILES as HARDENING_CONFINED_PROFILES,
    install_command as hardening_install_command,
    install_script_path as hardening_install_script,
    is_apparmor_enabled,
    is_selinux_enabled,
    loaded_confined_domains as hardening_loaded_confined_domains,
    loaded_confined_profiles as hardening_loaded_confined_profiles,
    profile_modes as hardening_profile_modes,
)
from terok_clearance.runtime.installer import (
    check_units_outdated,
    install_notifier_service,
    read_installed_notifier_unit_version,
    read_installed_unit_version,
    uninstall_notifier_service,
    uninstall_service,
)
from terok_clearance.runtime.service import configure_logging, wait_for_shutdown_signal
from terok_clearance.wire.errors import (
    InvalidAction,
    ShieldCliFailed,
    UnknownRequest,
    VerdictTupleMismatch,
)
from terok_clearance.wire.interface import CLEARANCE_INTERFACE_NAME, Clearance1Interface
from terok_clearance.wire.socket import default_clearance_socket_path

__all__ = [
    "CLEARANCE_INTERFACE_NAME",
    "CallbackNotifier",
    "Clearance1Interface",
    "ClearanceClient",
    "ClearanceEvent",
    "ClearanceHub",
    "DbusNotifier",
    "EventSubscriber",
    # Hardening (optional MAC layer)
    "HARDENING_CONFINED_DOMAINS",
    "HARDENING_CONFINED_PROFILES",
    "InvalidAction",
    "Notification",
    "Notifier",
    "NullNotifier",
    "ShieldCliFailed",
    "UnknownRequest",
    "VerdictTupleMismatch",
    "check_units_outdated",
    "configure_logging",
    "create_notifier",
    "default_clearance_socket_path",
    "hardening_install_command",
    "hardening_install_script",
    "hardening_loaded_confined_domains",
    "hardening_loaded_confined_profiles",
    "hardening_profile_modes",
    "install_notifier_service",
    "is_apparmor_enabled",
    "is_selinux_enabled",
    "read_installed_notifier_unit_version",
    "read_installed_unit_version",
    "serve",
    "uninstall_notifier_service",
    "uninstall_service",
    "wait_for_shutdown_signal",
]

__version__ = "0.0.0"
