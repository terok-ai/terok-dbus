# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Typed varlink errors the hub can raise from ``Verdict``.

Subclasses of `asyncvarlink.TypedVarlinkErrorReply` — the hub
raises one of these on the four refusal paths, and clients pattern-
match on the subclass instead of stringly-matching a message.  All
four share the ``org.terok.Clearance1`` interface namespace.
"""

from asyncvarlink import TypedVarlinkErrorReply

from terok_clearance.wire.interface import CLEARANCE_INTERFACE_NAME


class UnknownRequest(TypedVarlinkErrorReply, interface=CLEARANCE_INTERFACE_NAME, paramprefix=""):
    """``Verdict`` referenced a ``request_id`` the hub didn't emit.

    Fail-closed for the attacker's dream-up case: a peer connecting to
    the clearance socket synthesises a verdict for a block that was
    never broadcast.  No binding, no action.
    """

    class Parameters:
        """Typed payload for the varlink error reply."""

        request_id: str


class VerdictTupleMismatch(
    TypedVarlinkErrorReply, interface=CLEARANCE_INTERFACE_NAME, paramprefix=""
):
    """``(container, dest)`` don't match the hub's pending record.

    Cheap defence against replay attackers who sniffed a ``request_id``
    on this connection but try to apply a verdict against a different
    destination.  ``expected_*`` are what the hub recorded when it
    emitted ``connection_blocked``; ``got_*`` are what the call
    carried.
    """

    class Parameters:
        """Typed payload for the varlink error reply."""

        expected_container: str
        expected_dest: str
        got_container: str
        got_dest: str


class InvalidAction(TypedVarlinkErrorReply, interface=CLEARANCE_INTERFACE_NAME, paramprefix=""):
    """``action`` wasn't one of ``allow`` / ``deny``."""

    class Parameters:
        """Typed payload for the varlink error reply."""

        action: str


class ShieldCliFailed(TypedVarlinkErrorReply, interface=CLEARANCE_INTERFACE_NAME, paramprefix=""):
    """``terok-shield allow|deny`` exited non-zero or timed out.

    Clients render this as the red "Allow failed" / "Deny failed"
    popup variant: the user's click reached the hub but the firewall
    didn't accept it, so the notification's premise ("you decided X")
    is misleading.  ``stderr`` is whatever ``terok-shield`` wrote,
    truncated to a reasonable length by the hub.
    """

    class Parameters:
        """Typed payload for the varlink error reply."""

        action: str
        stderr: str
