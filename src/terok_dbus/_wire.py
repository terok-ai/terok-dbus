# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""The ``org.terok.Clearance1`` varlink interface — events out, verdicts in.

Subscribers call ``Subscribe()`` with ``more=true`` and receive a stream
of :class:`ClearanceEvent` records until the connection closes.  Verdict
clients call ``Verdict()`` as a regular RPC; the hub validates the
``(container, request_id, dest)`` triple against its live-pending state
before shelling out to ``terok-shield``.

The whole surface is typed-Python → :mod:`asyncvarlink` derives the
varlink IDL from these annotations, so there's no hand-authored
``.varlink`` file to drift from the code.  ``varlinkctl`` can still
introspect the service at runtime via the standard
``org.varlink.service.GetInterfaceDescription`` method.
"""

from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass

from asyncvarlink import TypedVarlinkErrorReply, VarlinkInterface, varlinkmethod

#: Interface name used for varlink dispatch and ``varlinkctl`` introspection.
#: The transport is a plain unix socket (no D-Bus daemon in the loop); the
#: name lives purely as the introspection identifier.
CLEARANCE_INTERFACE_NAME = "org.terok.Clearance1"


@dataclass
class ClearanceEvent:
    """One event fanned out to every ``Subscribe()`` caller.

    The ``type`` field discriminates the payload; other fields are
    optional and populated per-kind.  Varlink IDL doesn't model sum
    types directly, so the flat-with-optionals shape is idiomatic —
    the same pattern ``io.systemd.Resolve.Monitor`` uses.  Consumers
    switch on ``type`` and read the matching subset.

    Known values of ``type``:

    * ``connection_blocked`` — sets ``request_id``, ``dest``, ``port``,
      ``proto``, ``domain``.  Requires an operator verdict.
    * ``verdict_applied`` — sets ``request_id``, ``action``, ``ok``.
    * ``container_started`` — just ``container``.
    * ``container_exited`` — ``container`` + ``reason``.
    * ``shield_up`` / ``shield_down`` / ``shield_down_all`` — just
      ``container``.

    Unknown values are forwarded unchanged so the wire format can grow
    without breaking clients pinned to older schemas.
    """

    type: str
    container: str
    request_id: str = ""
    dest: str = ""
    port: int = 0
    proto: int = 0
    domain: str = ""
    action: str = ""
    ok: bool = False
    reason: str = ""


class UnknownRequest(TypedVarlinkErrorReply, interface=CLEARANCE_INTERFACE_NAME, paramprefix=""):
    """Varlink error — ``Verdict`` referenced a ``request_id`` the hub didn't emit.

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
    """Varlink error — ``(container, dest)`` don't match the hub's pending record.

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
    """Varlink error — ``action`` wasn't one of ``allow`` / ``deny``."""

    class Parameters:
        """Typed payload for the varlink error reply."""

        action: str


class ShieldCliFailed(TypedVarlinkErrorReply, interface=CLEARANCE_INTERFACE_NAME, paramprefix=""):
    """Varlink error — ``terok-shield allow|deny`` exited non-zero or timed out.

    Clients render this as the red "Allow failed" / "Deny failed"
    popup variant: the user's click reached the hub but the firewall
    didn't accept it, so the notification's premise ("you decided X")
    is misleading.  ``stderr`` is whatever ``terok-shield`` wrote to
    its stderr, truncated to a reasonable length by the hub.
    """

    class Parameters:
        """Typed payload for the varlink error reply."""

        action: str
        stderr: str


class Clearance1Interface(VarlinkInterface, name=CLEARANCE_INTERFACE_NAME):
    """Varlink interface served by the clearance hub.

    Two callables are injected so the state machine stays testable
    without a live varlink connection:

    * ``event_stream_factory`` — returns a fresh ``AsyncIterator``
      yielding :class:`ClearanceEvent` instances.  The hub owns one
      per connected subscriber so backpressure is local to the slow
      client.
    * ``apply_verdict`` — validates the triple and, on success, shells
      out to ``terok-shield``.  Raises a typed varlink error for any
      refusal path; returns ``True`` only when the shield invocation
      itself succeeded.
    """

    def __init__(
        self,
        event_stream_factory: Callable[[], AsyncIterator[ClearanceEvent]],
        apply_verdict: Callable[[str, str, str, str], Awaitable[bool]],
    ) -> None:
        """Bind the per-subscriber event stream factory and the verdict callable."""
        self._event_stream_factory = event_stream_factory
        self._apply_verdict = apply_verdict

    @varlinkmethod(return_parameter="event")
    async def Subscribe(self) -> AsyncIterator[ClearanceEvent]:  # noqa: N802
        """Stream hub events to this caller until the connection closes."""
        async for event in self._event_stream_factory():
            yield event

    @varlinkmethod(return_parameter="ok")
    async def Verdict(  # noqa: N802
        self, *, container: str, request_id: str, dest: str, action: str
    ) -> bool:
        """Apply *action* (``allow`` / ``deny``) to *dest* for *container*.

        Returns ``True`` when ``terok-shield`` accepted the verdict.
        Raises :class:`UnknownRequest`, :class:`VerdictTupleMismatch`,
        :class:`InvalidAction`, or :class:`ShieldCliFailed` for the
        four refusal paths — clients get a typed error they can render
        without stringly-matching the message.
        """
        return await self._apply_verdict(container, request_id, dest, action)
