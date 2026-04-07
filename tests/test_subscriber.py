# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for EventSubscriber — senderless signal subscription with instance discovery."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from dbus_fast import MessageType
from dbus_fast.message import Message

from terok_dbus._interfaces import (
    CLEARANCE_BUS_NAME,
    CLEARANCE_INTERFACE_NAME,
    CLEARANCE_OBJECT_PATH,
    SHIELD_BUS_NAME_PREFIX,
    SHIELD_INTERFACE_NAME,
    SHIELD_OBJECT_PATH,
)
from terok_dbus._subscriber import EventSubscriber
from tests.conftest import (
    CONTAINER,
    DEST_IP,
    DOMAIN,
    PROJECT,
    REASON,
    RESOLVED_IPS,
    TASK,
)

# ── Test data ─────────────────────────────────────────────────────────

_BRIDGE_BUS_NAME = f"{SHIELD_BUS_NAME_PREFIX}abc123"
_BRIDGE_UNIQUE = ":1.42"
_CLEARANCE_UNIQUE = ":1.99"


# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def mock_notifier() -> AsyncMock:
    """A mock satisfying the Notifier protocol."""
    notifier = AsyncMock()
    notifier.notify = AsyncMock(return_value=42)
    notifier.on_action = AsyncMock()
    notifier.close = AsyncMock()
    notifier.disconnect = AsyncMock()
    return notifier


def _make_mock_bus(
    shield_names: list[str] | None = None,
    clearance_owner: str | None = None,
) -> MagicMock:
    """Create a mock MessageBus that handles AddMatch, ListNames, GetNameOwner."""
    bus = MagicMock()
    bus.add_message_handler = MagicMock()
    bus.remove_message_handler = MagicMock()
    bus.disconnect = MagicMock()

    all_names = list(shield_names or [_BRIDGE_BUS_NAME])
    if clearance_owner:
        all_names.append(CLEARANCE_BUS_NAME)

    async def mock_call(msg: Message) -> MagicMock:
        reply = MagicMock()
        if msg.member == "ListNames":
            reply.body = [all_names]
        elif msg.member == "GetNameOwner":
            name = msg.body[0]
            if name.startswith(SHIELD_BUS_NAME_PREFIX):
                reply.body = [_BRIDGE_UNIQUE]
            elif name == CLEARANCE_BUS_NAME and clearance_owner:
                reply.body = [clearance_owner]
            else:
                reply.body = [":1.1"]
        elif msg.member in ("AddMatch", "RemoveMatch"):
            reply.body = []
        elif msg.member in ("Verdict", "Resolve"):
            reply.body = [True]
        else:
            reply.body = []
        return reply

    bus.call = AsyncMock(side_effect=mock_call)
    return bus


@pytest.fixture
def mock_bus() -> MagicMock:
    """A pre-wired mock bus with one shield bridge."""
    return _make_mock_bus()


def _make_shield_signal(
    member: str,
    body: list,
    sender: str = _BRIDGE_UNIQUE,
) -> Message:
    """Create a fake Shield1 signal message."""
    msg = MagicMock(spec=Message)
    msg.message_type = MessageType.SIGNAL
    msg.interface = SHIELD_INTERFACE_NAME
    msg.path = SHIELD_OBJECT_PATH
    msg.member = member
    msg.sender = sender
    msg.body = body
    return msg


def _make_clearance_signal(
    member: str,
    body: list,
    sender: str = _CLEARANCE_UNIQUE,
) -> Message:
    """Create a fake Clearance1 signal message."""
    msg = MagicMock(spec=Message)
    msg.message_type = MessageType.SIGNAL
    msg.interface = CLEARANCE_INTERFACE_NAME
    msg.path = CLEARANCE_OBJECT_PATH
    msg.member = member
    msg.sender = sender
    msg.body = body
    return msg


def _make_noc_signal(name: str, old_owner: str, new_owner: str) -> Message:
    """Create a fake NameOwnerChanged signal."""
    msg = MagicMock(spec=Message)
    msg.message_type = MessageType.SIGNAL
    msg.interface = "org.freedesktop.DBus"
    msg.path = "/org/freedesktop/DBus"
    msg.member = "NameOwnerChanged"
    msg.sender = "org.freedesktop.DBus"
    msg.body = [name, old_owner, new_owner]
    return msg


def _get_handler(bus: MagicMock):
    """Extract the message handler registered on the bus."""
    return bus.add_message_handler.call_args[0][0]


# ── Start / subscription tests ────────────────────────────────────────


class TestEventSubscriberStart:
    """Subscription setup tests."""

    async def test_adds_senderless_match_rules(self, mock_bus: MagicMock, mock_notifier: AsyncMock):
        """Start() installs senderless match rules for Shield1 and Clearance1."""
        sub = EventSubscriber(mock_notifier, bus=mock_bus)
        await sub.start()

        add_match_calls = [c for c in mock_bus.call.call_args_list if c[0][0].member == "AddMatch"]
        rules = [c[0][0].body[0] for c in add_match_calls]

        # 4 rules: 2x NOC (shield prefix + clearance exact), Shield1, Clearance1
        assert len(rules) == 4
        # NOC rules are narrowed with arg0namespace / arg0
        noc_rules = [r for r in rules if "NameOwnerChanged" in r]
        assert len(noc_rules) == 2
        assert any("arg0namespace=" in r for r in noc_rules)
        assert any("arg0=" in r for r in noc_rules)
        # Shield1 signal rule has no sender=
        shield_rule = [r for r in rules if SHIELD_INTERFACE_NAME in r and "NameOwner" not in r][0]
        assert "sender=" not in shield_rule
        assert f"interface='{SHIELD_INTERFACE_NAME}'" in shield_rule
        # Clearance1 signal rule has no sender=
        clearance_rule = [
            r for r in rules if CLEARANCE_INTERFACE_NAME in r and "NameOwner" not in r
        ][0]
        assert "sender=" not in clearance_rule

        await sub.stop()

    async def test_discovers_existing_bridges(self, mock_bus: MagicMock, mock_notifier: AsyncMock):
        """Start() discovers existing shield bridges via ListNames."""
        sub = EventSubscriber(mock_notifier, bus=mock_bus)
        await sub.start()

        assert _BRIDGE_BUS_NAME in sub._known_shields
        assert sub._known_shields[_BRIDGE_BUS_NAME] == _BRIDGE_UNIQUE
        await sub.stop()

    async def test_registers_message_handler(self, mock_bus: MagicMock, mock_notifier: AsyncMock):
        """Start() registers a unified message handler."""
        sub = EventSubscriber(mock_notifier, bus=mock_bus)
        await sub.start()

        mock_bus.add_message_handler.assert_called_once()
        await sub.stop()

    async def test_creates_bus_when_none_injected(self, mock_notifier: AsyncMock):
        """Creates a new bus connection when none is provided."""
        bus = _make_mock_bus()
        bus.connect = AsyncMock(return_value=bus)
        with patch("terok_dbus._subscriber.MessageBus", return_value=bus):
            sub = EventSubscriber(mock_notifier)
            await sub.start()
            bus.connect.assert_awaited_once()
            await sub.stop()


# ── Shield1 signal handling ───────────────────────────────────────────


class TestEventSubscriberShield:
    """Shield1 signal handling tests."""

    async def test_connection_blocked_creates_notification(
        self, mock_bus: MagicMock, mock_notifier: AsyncMock
    ):
        """ConnectionBlocked from a known bridge creates a notification."""
        sub = EventSubscriber(mock_notifier, bus=mock_bus)
        await sub.start()

        handler = _get_handler(mock_bus)
        handler(
            _make_shield_signal(
                "ConnectionBlocked",
                [CONTAINER, DEST_IP, 443, 6, DOMAIN, "req-1"],
            )
        )
        await asyncio.sleep(0)

        mock_notifier.notify.assert_awaited_once()
        call_kwargs = mock_notifier.notify.call_args
        assert f"Blocked: {DOMAIN}:443" in call_kwargs[0][0]
        assert ("accept", "Allow") in call_kwargs.kwargs["actions"]
        await sub.stop()

    async def test_connection_blocked_uses_dest_when_no_domain(
        self, mock_bus: MagicMock, mock_notifier: AsyncMock
    ):
        """Falls back to IP when domain is empty."""
        sub = EventSubscriber(mock_notifier, bus=mock_bus)
        await sub.start()

        handler = _get_handler(mock_bus)
        handler(
            _make_shield_signal(
                "ConnectionBlocked",
                [CONTAINER, DEST_IP, 80, 6, "", "req-2"],
            )
        )
        await asyncio.sleep(0)

        summary = mock_notifier.notify.call_args[0][0]
        assert f"{DEST_IP}:80" in summary
        await sub.stop()

    async def test_connection_blocked_tracks_sender(
        self, mock_bus: MagicMock, mock_notifier: AsyncMock
    ):
        """ConnectionBlocked records the signal sender for verdict routing."""
        sub = EventSubscriber(mock_notifier, bus=mock_bus)
        await sub.start()

        handler = _get_handler(mock_bus)
        handler(
            _make_shield_signal(
                "ConnectionBlocked",
                [CONTAINER, DEST_IP, 443, 6, DOMAIN, "req-1"],
            )
        )
        await asyncio.sleep(0)

        assert sub._request_senders["req-1"] == _BRIDGE_UNIQUE
        await sub.stop()

    async def test_connection_blocked_ignores_unknown_sender(
        self, mock_bus: MagicMock, mock_notifier: AsyncMock
    ):
        """Signals from unknown senders are silently ignored."""
        sub = EventSubscriber(mock_notifier, bus=mock_bus)
        await sub.start()

        handler = _get_handler(mock_bus)
        handler(
            _make_shield_signal(
                "ConnectionBlocked",
                [CONTAINER, DEST_IP, 443, 6, DOMAIN, "req-1"],
                sender=":1.999",  # not in known_shields
            )
        )
        await asyncio.sleep(0)

        mock_notifier.notify.assert_not_awaited()
        await sub.stop()

    async def test_action_routes_verdict_to_sender(
        self, mock_bus: MagicMock, mock_notifier: AsyncMock
    ):
        """Verdict method call is sent to the bridge that emitted the signal."""
        sub = EventSubscriber(mock_notifier, bus=mock_bus)
        await sub.start()

        handler = _get_handler(mock_bus)
        handler(
            _make_shield_signal(
                "ConnectionBlocked",
                [CONTAINER, DEST_IP, 443, 6, DOMAIN, "req-1"],
            )
        )
        await asyncio.sleep(0)

        # Extract and invoke the action callback
        action_cb = mock_notifier.on_action.call_args[0][1]
        action_cb("accept")
        await asyncio.sleep(0)

        # Find the Verdict method call
        verdict_calls = [c for c in mock_bus.call.call_args_list if c[0][0].member == "Verdict"]
        assert len(verdict_calls) == 1
        verdict_msg = verdict_calls[0][0][0]
        assert verdict_msg.destination == _BRIDGE_UNIQUE
        assert verdict_msg.body == ["req-1", "accept"]
        await sub.stop()

    async def test_verdict_applied_updates_notification(
        self, mock_bus: MagicMock, mock_notifier: AsyncMock
    ):
        """VerdictApplied replaces the original notification."""
        sub = EventSubscriber(mock_notifier, bus=mock_bus)
        await sub.start()
        handler = _get_handler(mock_bus)

        # ConnectionBlocked (creates notification id=42)
        handler(
            _make_shield_signal(
                "ConnectionBlocked",
                [CONTAINER, DEST_IP, 443, 6, DOMAIN, "req-1"],
            )
        )
        await asyncio.sleep(0)

        mock_notifier.notify.reset_mock()
        handler(
            _make_shield_signal(
                "VerdictApplied",
                [CONTAINER, DEST_IP, "req-1", "accept", True],
            )
        )
        await asyncio.sleep(0)

        mock_notifier.notify.assert_awaited_once()
        assert mock_notifier.notify.call_args.kwargs["replaces_id"] == 42
        assert "Allowed" in mock_notifier.notify.call_args[0][0]
        await sub.stop()


# ── Clearance1 signal handling ────────────────────────────────────────


class TestEventSubscriberClearance:
    """Clearance1 signal handling tests."""

    async def test_request_received_creates_notification(self, mock_notifier: AsyncMock):
        """RequestReceived from the clearance daemon creates a notification."""
        bus = _make_mock_bus(clearance_owner=_CLEARANCE_UNIQUE)
        sub = EventSubscriber(mock_notifier, bus=bus)
        await sub.start()

        handler = _get_handler(bus)
        handler(
            _make_clearance_signal(
                "RequestReceived",
                ["req-10", PROJECT, TASK, DOMAIN, 443, REASON],
            )
        )
        await asyncio.sleep(0)

        mock_notifier.notify.assert_awaited_once()
        summary = mock_notifier.notify.call_args[0][0]
        assert TASK in summary
        assert f"{DOMAIN}:443" in summary
        await sub.stop()

    async def test_action_routes_resolve_to_sender(self, mock_notifier: AsyncMock):
        """Resolve method call is sent to the clearance daemon that emitted the signal."""
        bus = _make_mock_bus(clearance_owner=_CLEARANCE_UNIQUE)
        sub = EventSubscriber(mock_notifier, bus=bus)
        await sub.start()

        handler = _get_handler(bus)
        handler(
            _make_clearance_signal(
                "RequestReceived",
                ["req-10", PROJECT, TASK, DOMAIN, 443, REASON],
            )
        )
        await asyncio.sleep(0)

        action_cb = mock_notifier.on_action.call_args[0][1]
        action_cb("deny")
        await asyncio.sleep(0)

        resolve_calls = [c for c in bus.call.call_args_list if c[0][0].member == "Resolve"]
        assert len(resolve_calls) == 1
        assert resolve_calls[0][0][0].destination == _CLEARANCE_UNIQUE
        assert resolve_calls[0][0][0].body == ["req-10", "deny"]
        await sub.stop()

    async def test_request_resolved_updates_notification(self, mock_notifier: AsyncMock):
        """RequestResolved replaces the original notification."""
        bus = _make_mock_bus(clearance_owner=_CLEARANCE_UNIQUE)
        sub = EventSubscriber(mock_notifier, bus=bus)
        await sub.start()
        handler = _get_handler(bus)

        handler(
            _make_clearance_signal(
                "RequestReceived",
                ["req-10", PROJECT, TASK, DOMAIN, 443, REASON],
            )
        )
        await asyncio.sleep(0)

        mock_notifier.notify.reset_mock()
        handler(
            _make_clearance_signal(
                "RequestResolved",
                ["req-10", "accept", RESOLVED_IPS],
            )
        )
        await asyncio.sleep(0)

        mock_notifier.notify.assert_awaited_once()
        assert mock_notifier.notify.call_args.kwargs["replaces_id"] == 42
        assert "Approved" in mock_notifier.notify.call_args[0][0]
        await sub.stop()


# ── Instance discovery ────────────────────────────────────────────────


class TestInstanceDiscovery:
    """NameOwnerChanged-driven bridge lifecycle tests."""

    async def test_new_bridge_added_to_registry(
        self, mock_bus: MagicMock, mock_notifier: AsyncMock
    ):
        """NameOwnerChanged with new_owner adds bridge to known_shields."""
        sub = EventSubscriber(mock_notifier, bus=mock_bus)
        await sub.start()

        handler = _get_handler(mock_bus)
        new_bridge = f"{SHIELD_BUS_NAME_PREFIX}def456"
        handler(_make_noc_signal(new_bridge, "", ":1.55"))

        assert new_bridge in sub._known_shields
        assert sub._known_shields[new_bridge] == ":1.55"
        await sub.stop()

    async def test_bridge_disappearance_cleans_registry(
        self, mock_bus: MagicMock, mock_notifier: AsyncMock
    ):
        """NameOwnerChanged with empty new_owner removes bridge and stale pending."""
        sub = EventSubscriber(mock_notifier, bus=mock_bus)
        await sub.start()

        handler = _get_handler(mock_bus)
        # Simulate a blocked connection from the known bridge
        handler(
            _make_shield_signal(
                "ConnectionBlocked",
                [CONTAINER, DEST_IP, 443, 6, DOMAIN, "req-1"],
            )
        )
        await asyncio.sleep(0)
        assert "req-1" in sub._request_senders

        # Bridge disappears
        handler(_make_noc_signal(_BRIDGE_BUS_NAME, _BRIDGE_UNIQUE, ""))

        assert _BRIDGE_BUS_NAME not in sub._known_shields
        assert "req-1" not in sub._request_senders
        await sub.stop()

    async def test_unrelated_name_changes_ignored(
        self, mock_bus: MagicMock, mock_notifier: AsyncMock
    ):
        """NameOwnerChanged for unrelated bus names is ignored."""
        sub = EventSubscriber(mock_notifier, bus=mock_bus)
        await sub.start()

        handler = _get_handler(mock_bus)
        handler(_make_noc_signal("org.unrelated.Service", "", ":1.77"))

        assert len(sub._known_shields) == 1  # only the original bridge
        await sub.stop()

    async def test_signals_accepted_after_dynamic_discovery(
        self, mock_bus: MagicMock, mock_notifier: AsyncMock
    ):
        """Signals from a dynamically discovered bridge are accepted."""
        sub = EventSubscriber(mock_notifier, bus=mock_bus)
        await sub.start()

        handler = _get_handler(mock_bus)
        new_bridge = f"{SHIELD_BUS_NAME_PREFIX}def456"
        new_unique = ":1.55"

        # Bridge appears
        handler(_make_noc_signal(new_bridge, "", new_unique))

        # Signal from the new bridge
        handler(
            _make_shield_signal(
                "ConnectionBlocked",
                [CONTAINER, DEST_IP, 443, 6, DOMAIN, "req-new"],
                sender=new_unique,
            )
        )
        await asyncio.sleep(0)

        mock_notifier.notify.assert_awaited_once()
        assert sub._request_senders["req-new"] == new_unique
        await sub.stop()


# ── Stop / cleanup ────────────────────────────────────────────────────


class TestEventSubscriberStop:
    """Teardown tests."""

    async def test_stop_removes_message_handler(
        self, mock_bus: MagicMock, mock_notifier: AsyncMock
    ):
        """Stop() removes the message handler."""
        sub = EventSubscriber(mock_notifier, bus=mock_bus)
        await sub.start()
        await sub.stop()
        mock_bus.remove_message_handler.assert_called_once()

    async def test_stop_sends_remove_match(self, mock_bus: MagicMock, mock_notifier: AsyncMock):
        """Stop() sends RemoveMatch for all registered rules."""
        sub = EventSubscriber(mock_notifier, bus=mock_bus)
        await sub.start()
        await sub.stop()

        remove_calls = [c for c in mock_bus.call.call_args_list if c[0][0].member == "RemoveMatch"]
        assert len(remove_calls) == 4  # 2x NOC + Shield1 + Clearance1

    async def test_stop_clears_state(self, mock_bus: MagicMock, mock_notifier: AsyncMock):
        """Stop() clears all internal tracking state."""
        sub = EventSubscriber(mock_notifier, bus=mock_bus)
        await sub.start()
        # Add some state
        sub._request_senders["req-1"] = _BRIDGE_UNIQUE
        sub._pending[42] = "req-1"
        await sub.stop()

        assert not sub._known_shields
        assert not sub._request_senders
        assert not sub._pending
        assert not sub._match_rules

    async def test_stop_disconnects_owned_bus(self, mock_notifier: AsyncMock):
        """Stop() disconnects the bus if it was created internally."""
        bus = _make_mock_bus()
        bus.connect = AsyncMock(return_value=bus)
        with patch("terok_dbus._subscriber.MessageBus", return_value=bus):
            sub = EventSubscriber(mock_notifier)
            await sub.start()
            await sub.stop()
            bus.disconnect.assert_called_once()

    async def test_stop_does_not_disconnect_injected_bus(
        self, mock_bus: MagicMock, mock_notifier: AsyncMock
    ):
        """Stop() does not disconnect a bus provided by the caller."""
        sub = EventSubscriber(mock_notifier, bus=mock_bus)
        await sub.start()
        await sub.stop()
        mock_bus.disconnect.assert_not_called()
