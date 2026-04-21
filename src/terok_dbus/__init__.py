# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""D-Bus desktop notification package for terok."""

import logging

from dbus_fast import DBusError

from terok_dbus._callback import CallbackNotifier, Notification
from terok_dbus._interfaces import (
    CLEARANCE_BUS_NAME,
    CLEARANCE_INTERFACE_NAME,
    CLEARANCE_OBJECT_PATH,
    CLEARANCE_XML,
    SHIELD_BUS_NAME,
    SHIELD_INTERFACE_NAME,
    SHIELD_OBJECT_PATH,
    SHIELD_XML,
)
from terok_dbus._notifier import DbusNotifier
from terok_dbus._null import NullNotifier
from terok_dbus._protocol import Notifier
from terok_dbus._subscriber import EventSubscriber

__all__ = [
    "CallbackNotifier",
    "DbusNotifier",
    "EventSubscriber",
    "Notification",
    "NullNotifier",
    "Notifier",
    "create_notifier",
    "CLEARANCE_BUS_NAME",
    "CLEARANCE_INTERFACE_NAME",
    "CLEARANCE_OBJECT_PATH",
    "CLEARANCE_XML",
    "SHIELD_BUS_NAME",
    "SHIELD_INTERFACE_NAME",
    "SHIELD_OBJECT_PATH",
    "SHIELD_XML",
]

__version__ = "0.0.0"

_log = logging.getLogger(__name__)


async def create_notifier(app_name: str = "terok") -> Notifier:
    """Return a connected ``DbusNotifier``, or a ``NullNotifier`` on failure.

    This is the primary entry point. Callers get a working notifier without
    caring whether a D-Bus session bus is available.

    Args:
        app_name: Application name sent with every notification.

    Returns:
        A ``Notifier``-compatible instance.
    """
    notifier = DbusNotifier(app_name)
    try:
        await notifier.connect()
    except (OSError, DBusError, ValueError) as exc:
        _log.debug("D-Bus session bus unavailable, falling back to NullNotifier: %s", exc)
        return NullNotifier()
    return notifier
