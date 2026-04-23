# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""The ``org.terok.ClearanceVerdict1`` varlink interface.

One method — ``Apply(container, dest, action)`` returning
``(ok, stderr)`` — bridging the hardened hub to the unhardened
verdict helper that actually execs ``terok-shield allow|deny``.

The interface is dumb on purpose: the hub already did the authz
check (request_id matches the emitted ``connection_blocked``
triple); the helper just forwards to shield and passes the outcome
back.  Security-critical invariants stay on the hub side where
their caller-trust story is easiest to audit.
"""

from typing import TypedDict

from asyncvarlink import VarlinkInterface, varlinkmethod

#: Interface name used for varlink dispatch and ``varlinkctl`` introspection.
VERDICT_INTERFACE_NAME = "org.terok.ClearanceVerdict1"


class VerdictReply(TypedDict):
    """Two-field reply from ``Apply``; also the varlink IDL shape."""

    ok: bool
    stderr: str


class Verdict1Interface(VarlinkInterface, name=VERDICT_INTERFACE_NAME):
    """Minimal varlink interface served by the verdict helper.

    ``apply_verdict`` is injected so the interface stays testable
    without a live shield subprocess.  Async because the hub client
    awaits on it; the helper's implementation is async anyway.
    """

    def __init__(self, apply_verdict):
        """Bind the verdict-dispatch callable."""
        self._apply_verdict = apply_verdict

    @varlinkmethod()
    async def Apply(  # noqa: N802
        self, *, container: str, dest: str, action: str
    ) -> VerdictReply:
        """Run ``terok-shield <action> <container> <dest>`` and report the outcome.

        The helper never raises — spawn failure, non-zero exit, and
        timeout all fold into ``ok=False`` with a reason string the
        hub re-raises to its own client as
        :class:`~terok_clearance.wire.errors.ShieldCliFailed`.
        """
        ok, stderr = await self._apply_verdict(container, dest, action)
        return VerdictReply(ok=ok, stderr=stderr)
