# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the varlink interface + event/error types in ``_wire``."""

from __future__ import annotations

import pytest

from terok_dbus._wire import (
    CLEARANCE_INTERFACE_NAME,
    Clearance1Interface,
    ClearanceEvent,
    InvalidAction,
    ShieldCliFailed,
    UnknownRequest,
    VerdictTupleMismatch,
)


class TestClearanceEvent:
    """The flat-with-optionals event shape all varlink subscribers see."""

    def test_default_fields_are_empty(self) -> None:
        """Only ``type`` + ``container`` are required; the rest default to empty."""
        event = ClearanceEvent(type="connection_blocked", container="c1")
        assert event.request_id == ""
        assert event.dest == ""
        assert event.port == 0
        assert event.proto == 0
        assert event.domain == ""
        assert event.action == ""
        assert event.ok is False
        assert event.reason == ""

    def test_fields_preserve_values(self) -> None:
        """Constructor assignment round-trips through public fields."""
        event = ClearanceEvent(
            type="connection_blocked",
            container="c1",
            request_id="c1:1",
            dest="1.1.1.1",
            port=443,
            proto=6,
            domain="example.test",
        )
        assert event.type == "connection_blocked"
        assert event.request_id == "c1:1"
        assert event.domain == "example.test"


class TestTypedErrors:
    """Varlink error replies carry a full ``org.terok.Clearance1.*`` name."""

    @pytest.mark.parametrize(
        ("cls", "kwargs", "expected_name"),
        [
            (
                UnknownRequest,
                {"request_id": "c1:1"},
                f"{CLEARANCE_INTERFACE_NAME}.UnknownRequest",
            ),
            (
                InvalidAction,
                {"action": "maybe"},
                f"{CLEARANCE_INTERFACE_NAME}.InvalidAction",
            ),
            (
                VerdictTupleMismatch,
                {
                    "expected_container": "c1",
                    "expected_dest": "1.1.1.1",
                    "got_container": "c2",
                    "got_dest": "2.2.2.2",
                },
                f"{CLEARANCE_INTERFACE_NAME}.VerdictTupleMismatch",
            ),
            (
                ShieldCliFailed,
                {"action": "allow", "stderr": "nft lock"},
                f"{CLEARANCE_INTERFACE_NAME}.ShieldCliFailed",
            ),
        ],
    )
    def test_error_name_and_parameters(self, cls: type, kwargs: dict, expected_name: str) -> None:
        """Each error exposes its parameters + a fully-qualified varlink name."""
        err = cls(**kwargs)
        assert err.name == expected_name
        assert err.parameters == kwargs
        # Parameter descriptors (paramprefix="") expose the fields by their
        # bare names; handy for client-side inspection without .parameters.
        for key, value in kwargs.items():
            assert getattr(err, key) == value


class TestInterfaceShape:
    """Ensure the interface class keeps the two methods varlinkctl expects."""

    def test_interface_name(self) -> None:
        """The class attaches the well-known ``org.terok.Clearance1`` name."""
        assert Clearance1Interface.name == CLEARANCE_INTERFACE_NAME

    def test_interface_has_subscribe_and_verdict(self) -> None:
        """Both RPC methods survive the decorator pass as callables."""
        assert callable(Clearance1Interface.Subscribe)
        assert callable(Clearance1Interface.Verdict)
