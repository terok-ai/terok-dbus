# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for Shield1 and Clearance1 D-Bus interface definitions."""

from dbus_fast.introspection import Node

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


class TestShieldConstants:
    """Shield1 bus name, path, and interface constants."""

    def test_bus_name(self):
        assert SHIELD_BUS_NAME == "org.terok.Shield"

    def test_object_path(self):
        assert SHIELD_OBJECT_PATH == "/org/terok/Shield"

    def test_interface_name(self):
        assert SHIELD_INTERFACE_NAME == "org.terok.Shield1"


class TestClearanceConstants:
    """Clearance1 bus name, path, and interface constants."""

    def test_bus_name(self):
        assert CLEARANCE_BUS_NAME == "org.terok.Clearance"

    def test_object_path(self):
        assert CLEARANCE_OBJECT_PATH == "/org/terok/Clearance"

    def test_interface_name(self):
        assert CLEARANCE_INTERFACE_NAME == "org.terok.Clearance1"


class TestShieldXml:
    """Shield1 introspection XML parses correctly."""

    def test_parses(self):
        node = Node.parse(SHIELD_XML)
        assert len(node.interfaces) == 1
        assert node.interfaces[0].name == SHIELD_INTERFACE_NAME

    def test_connection_blocked_signal(self):
        iface = Node.parse(SHIELD_XML).interfaces[0]
        signals = {s.name: s for s in iface.signals}
        assert "ConnectionBlocked" in signals
        args = [(a.name, a.signature) for a in signals["ConnectionBlocked"].args]
        assert args == [
            ("container", "s"),
            ("dest", "s"),
            ("port", "q"),
            ("proto", "q"),
            ("domain", "s"),
            ("request_id", "s"),
        ]

    def test_verdict_method(self):
        iface = Node.parse(SHIELD_XML).interfaces[0]
        methods = {m.name: m for m in iface.methods}
        assert "Verdict" in methods
        m = methods["Verdict"]
        assert [(a.name, a.signature) for a in m.in_args] == [
            ("request_id", "s"),
            ("action", "s"),
        ]
        assert [(a.name, a.signature) for a in m.out_args] == [("ok", "b")]

    def test_verdict_applied_signal(self):
        iface = Node.parse(SHIELD_XML).interfaces[0]
        signals = {s.name: s for s in iface.signals}
        assert "VerdictApplied" in signals
        args = [(a.name, a.signature) for a in signals["VerdictApplied"].args]
        assert args == [
            ("container", "s"),
            ("dest", "s"),
            ("request_id", "s"),
            ("action", "s"),
            ("ok", "b"),
        ]


class TestClearanceXml:
    """Clearance1 introspection XML parses correctly."""

    def test_parses(self):
        node = Node.parse(CLEARANCE_XML)
        assert len(node.interfaces) == 1
        assert node.interfaces[0].name == CLEARANCE_INTERFACE_NAME

    def test_request_received_signal(self):
        iface = Node.parse(CLEARANCE_XML).interfaces[0]
        signals = {s.name: s for s in iface.signals}
        assert "RequestReceived" in signals
        args = [(a.name, a.signature) for a in signals["RequestReceived"].args]
        assert args == [
            ("request_id", "s"),
            ("project", "s"),
            ("task", "s"),
            ("dest", "s"),
            ("port", "q"),
            ("reason", "s"),
        ]

    def test_resolve_method(self):
        iface = Node.parse(CLEARANCE_XML).interfaces[0]
        methods = {m.name: m for m in iface.methods}
        assert "Resolve" in methods
        m = methods["Resolve"]
        assert [(a.name, a.signature) for a in m.in_args] == [
            ("request_id", "s"),
            ("action", "s"),
        ]
        assert [(a.name, a.signature) for a in m.out_args] == [("ok", "b")]

    def test_list_pending_method(self):
        iface = Node.parse(CLEARANCE_XML).interfaces[0]
        methods = {m.name: m for m in iface.methods}
        assert "ListPending" in methods
        m = methods["ListPending"]
        assert len(m.in_args) == 0
        assert m.out_args[0].name == "requests"
        assert m.out_args[0].signature == "a(ssssqs)"

    def test_request_resolved_signal(self):
        iface = Node.parse(CLEARANCE_XML).interfaces[0]
        signals = {s.name: s for s in iface.signals}
        assert "RequestResolved" in signals
        args = [(a.name, a.signature) for a in signals["RequestResolved"].args]
        assert args == [
            ("request_id", "s"),
            ("action", "s"),
            ("ips", "as"),
        ]
