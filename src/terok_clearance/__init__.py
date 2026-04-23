# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Clearance hub + desktop notification library for terok.

Two unrelated wire formats live under this one package:

* ``org.terok.Clearance1`` over a unix-socket **varlink** transport —
  the hub (:class:`ClearanceHub`) and the client library
  (:class:`ClearanceClient`, :class:`EventSubscriber`) that drive the
  per-container block / verdict / lifecycle flow.
* ``org.freedesktop.Notifications`` over **D-Bus** — the
  :class:`DbusNotifier` wrapper that renders those events as desktop
  popups.  Kept because that's the OS API; every other D-Bus path in
  this package (``org.terok.Shield1``) was removed in favour of the
  varlink transport.
"""

from terok_clearance.client.client import ClearanceClient
from terok_clearance.client.subscriber import EventSubscriber
from terok_clearance.domain.events import ClearanceEvent
from terok_clearance.domain.identity import ContainerIdentity
from terok_clearance.hub.server import ClearanceHub, serve
from terok_clearance.notifications.callback import CallbackNotifier, Notification
from terok_clearance.notifications.desktop import DbusNotifier
from terok_clearance.notifications.factory import create_notifier
from terok_clearance.notifications.null import NullNotifier
from terok_clearance.notifications.protocol import Notifier
from terok_clearance.runtime.installer import (
    check_units_outdated,
    read_installed_unit_version,
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
    "ContainerIdentity",
    "DbusNotifier",
    "EventSubscriber",
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
    "read_installed_unit_version",
    "serve",
    "uninstall_service",
    "wait_for_shutdown_signal",
]

__version__ = "0.0.0"
