# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""The ``org.terok.Clearance1`` varlink interface — events out, verdicts in.

Subscribers call ``Subscribe()`` with ``more=true`` and receive a stream
of [`ClearanceEvent`][terok_clearance.domain.events.ClearanceEvent] records until
the connection closes.  Verdict clients call ``Verdict()`` as a regular
RPC; the hub validates the ``(container, request_id, dest)`` triple
against its live-pending state before shelling out to ``terok-shield``.

The whole surface is typed-Python → `asyncvarlink` derives the
varlink IDL from these annotations, so there's no hand-authored
``.varlink`` file to drift from the code.  ``varlinkctl`` can still
introspect the service at runtime via the standard
``org.varlink.service.GetInterfaceDescription`` method.
"""

from collections.abc import AsyncIterator, Awaitable, Callable

from asyncvarlink import VarlinkInterface, varlinkmethod

from terok_clearance.domain.events import ClearanceEvent

#: Interface name used for varlink dispatch and ``varlinkctl`` introspection.
#: The transport is a plain unix socket (no D-Bus daemon in the loop); the
#: name lives purely as the introspection identifier.
CLEARANCE_INTERFACE_NAME = "org.terok.Clearance1"


class Clearance1Interface(VarlinkInterface, name=CLEARANCE_INTERFACE_NAME):
    """Varlink interface served by the clearance hub.

    Two callables are injected so the state machine stays testable
    without a live varlink connection:

    * ``event_stream_factory`` — returns a fresh ``AsyncIterator``
      yielding [`ClearanceEvent`][terok_clearance.ClearanceEvent] instances.  The hub owns one
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

    @varlinkmethod(return_parameter="event", delay_generator=False)
    async def Subscribe(self) -> AsyncIterator[ClearanceEvent]:  # noqa: N802
        """Stream hub events to this caller until the connection closes.

        Every yield is forwarded immediately with ``continues=true``;
        the stream ends only when the client disconnects.  A buffered
        (``delay_generator=True``) stream would hold the first event
        until a second arrives, breaking the "something just happened"
        liveness contract operators expect from a notification channel.
        """
        async for event in self._event_stream_factory():
            yield event

    @varlinkmethod(return_parameter="ok")
    async def Verdict(  # noqa: N802
        self, *, container: str, request_id: str, dest: str, action: str
    ) -> bool:
        """Apply *action* (``allow`` / ``deny``) to *dest* for *container*.

        Returns ``True`` when ``terok-shield`` accepted the verdict.
        Raises [`UnknownRequest`][terok_clearance.wire.errors.UnknownRequest],
        [`VerdictTupleMismatch`][terok_clearance.wire.errors.VerdictTupleMismatch],
        [`InvalidAction`][terok_clearance.wire.errors.InvalidAction], or
        [`ShieldCliFailed`][terok_clearance.wire.errors.ShieldCliFailed] on the
        four refusal paths — clients get a typed error they can render
        without stringly-matching the message.
        """
        return await self._apply_verdict(container, request_id, dest, action)
