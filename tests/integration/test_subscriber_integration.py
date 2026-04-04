# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for EventSubscriber — real D-Bus signals via dbus-fast ServiceInterface."""

import asyncio
from collections.abc import AsyncIterator
from unittest.mock import AsyncMock

import pytest
from dbus_fast.aio import MessageBus
from dbus_fast.service import ServiceInterface, method, signal

from terok_dbus._interfaces import (
    CLEARANCE_BUS_NAME,
    CLEARANCE_INTERFACE_NAME,
    CLEARANCE_OBJECT_PATH,
    SHIELD_BUS_NAME,
    SHIELD_INTERFACE_NAME,
    SHIELD_OBJECT_PATH,
)
from terok_dbus._subscriber import EventSubscriber
from tests.conftest import CONTAINER, DEST_IP, DOMAIN, DOMAIN_ALT, PROJECT, REASON, TASK

# ── Mock D-Bus services ───────────────────────────────────────────────


class MockShield1(ServiceInterface):
    """Mock implementation of org.terok.Shield1 for testing.

    dbus-fast signals derive their D-Bus type signature from the return
    annotation, not from parameter annotations.  The ``emit_*`` helpers
    stash arguments and call the bare signal method.
    """

    def __init__(self) -> None:
        super().__init__(SHIELD_INTERFACE_NAME)
        self._verdict_log: list[tuple[str, str]] = []
        self._sig_args: list = []

    @signal(name="ConnectionBlocked")
    def connection_blocked(self) -> "ssqqss":
        """Emit a ConnectionBlocked signal."""
        return self._sig_args

    def emit_connection_blocked(
        self, container: str, dest: str, port: int, proto: int, domain: str, request_id: str
    ) -> None:
        """Convenience emitter for ConnectionBlocked."""
        self._sig_args = [container, dest, port, proto, domain, request_id]
        self.connection_blocked()

    @method(name="Verdict")
    def verdict(self, request_id: "s", action: "s") -> "b":
        """Record a Verdict call and return success."""
        self._verdict_log.append((request_id, action))
        return True

    @signal(name="VerdictApplied")
    def verdict_applied(self) -> "ssssb":
        """Emit a VerdictApplied signal."""
        return self._sig_args

    def emit_verdict_applied(
        self, container: str, dest: str, request_id: str, action: str, ok: bool
    ) -> None:
        """Convenience emitter for VerdictApplied."""
        self._sig_args = [container, dest, request_id, action, ok]
        self.verdict_applied()


class MockClearance1(ServiceInterface):
    """Mock implementation of org.terok.Clearance1 for testing.

    Same pattern as ``MockShield1`` — return-type signals with emit helpers.
    """

    def __init__(self) -> None:
        super().__init__(CLEARANCE_INTERFACE_NAME)
        self._resolve_log: list[tuple[str, str]] = []
        self._sig_args: list = []

    @signal(name="RequestReceived")
    def request_received(self) -> "ssssqs":
        """Emit a RequestReceived signal."""
        return self._sig_args

    def emit_request_received(
        self, request_id: str, project: str, task: str, dest: str, port: int, reason: str
    ) -> None:
        """Convenience emitter for RequestReceived."""
        self._sig_args = [request_id, project, task, dest, port, reason]
        self.request_received()

    @method(name="Resolve")
    def resolve(self, request_id: "s", action: "s") -> "b":
        """Record a Resolve call and return success."""
        self._resolve_log.append((request_id, action))
        return True

    @signal(name="RequestResolved")
    def request_resolved(self) -> "ssas":
        """Emit a RequestResolved signal."""
        return self._sig_args

    def emit_request_resolved(self, request_id: str, action: str, ips: list[str]) -> None:
        """Convenience emitter for RequestResolved."""
        self._sig_args = [request_id, action, ips]
        self.request_resolved()


# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
async def shield_service(dbusmock_session) -> AsyncIterator[MockShield1]:
    """Export a MockShield1 service on the private test bus."""
    bus = await MessageBus().connect()
    svc = MockShield1()
    bus.export(SHIELD_OBJECT_PATH, svc)
    await bus.request_name(SHIELD_BUS_NAME)
    yield svc
    bus.disconnect()


@pytest.fixture
async def clearance_service(dbusmock_session) -> AsyncIterator[MockClearance1]:
    """Export a MockClearance1 service on the private test bus."""
    bus = await MessageBus().connect()
    svc = MockClearance1()
    bus.export(CLEARANCE_OBJECT_PATH, svc)
    await bus.request_name(CLEARANCE_BUS_NAME)
    yield svc
    bus.disconnect()


@pytest.fixture
async def subscriber_bus(dbusmock_session) -> AsyncIterator[MessageBus]:
    """A separate bus connection for the EventSubscriber."""
    bus = await MessageBus().connect()
    yield bus
    bus.disconnect()


# ── Tests ─────────────────────────────────────────────────────────────


@pytest.mark.needs_dbus
class TestShieldSubscriberIntegration:
    """Shield1 signal → notification → action → verdict flow on a real bus."""

    async def test_connection_blocked_creates_notification(
        self, shield_service: MockShield1, subscriber_bus: MessageBus
    ):
        mock_notifier = AsyncMock()
        mock_notifier.notify = AsyncMock(return_value=1)
        mock_notifier.on_action = AsyncMock()

        sub = EventSubscriber(mock_notifier, bus=subscriber_bus)
        await sub.start()

        # Allow signal subscriptions to settle
        await asyncio.sleep(0.1)

        shield_service.emit_connection_blocked(CONTAINER, DEST_IP, 443, 6, DOMAIN, "req-1")
        await asyncio.sleep(0.2)

        mock_notifier.notify.assert_awaited_once()
        call = mock_notifier.notify.call_args
        assert f"{DOMAIN}:443" in call[0][0]
        assert ("accept", "Allow") in call.kwargs["actions"]
        assert ("deny", "Deny") in call.kwargs["actions"]
        assert call.kwargs["hints"]["urgency"].value == 2  # critical
        assert call.kwargs["hints"]["resident"].value is True
        assert call.kwargs["timeout_ms"] == 0
        await sub.stop()

    async def test_action_routes_verdict_to_service(
        self, shield_service: MockShield1, subscriber_bus: MessageBus
    ):
        mock_notifier = AsyncMock()
        mock_notifier.notify = AsyncMock(return_value=1)
        mock_notifier.on_action = AsyncMock()

        sub = EventSubscriber(mock_notifier, bus=subscriber_bus)
        await sub.start()
        await asyncio.sleep(0.1)

        shield_service.emit_connection_blocked(CONTAINER, DEST_IP, 443, 6, DOMAIN_ALT, "req-2")
        await asyncio.sleep(0.2)

        # Simulate operator clicking "Allow"
        action_cb = mock_notifier.on_action.call_args[0][1]
        action_cb("accept")
        await asyncio.sleep(0.2)

        assert ("req-2", "accept") in shield_service._verdict_log
        await sub.stop()

    async def test_verdict_applied_updates_notification(
        self, shield_service: MockShield1, subscriber_bus: MessageBus
    ):
        mock_notifier = AsyncMock()
        mock_notifier.notify = AsyncMock(return_value=1)
        mock_notifier.on_action = AsyncMock()

        sub = EventSubscriber(mock_notifier, bus=subscriber_bus)
        await sub.start()
        await asyncio.sleep(0.1)

        # ConnectionBlocked creates notification (id=1)
        shield_service.emit_connection_blocked(CONTAINER, DEST_IP, 443, 6, DOMAIN, "req-3")
        await asyncio.sleep(0.2)

        # VerdictApplied updates it in-place
        mock_notifier.notify.reset_mock()
        shield_service.emit_verdict_applied(CONTAINER, DEST_IP, "req-3", "accept", True)
        await asyncio.sleep(0.2)

        mock_notifier.notify.assert_awaited_once()
        call = mock_notifier.notify.call_args
        assert call.kwargs["replaces_id"] == 1
        assert "Allowed" in call[0][0]
        assert call.kwargs["hints"]["urgency"].value == 1  # normal (resolved)
        await sub.stop()


@pytest.mark.needs_dbus
class TestClearanceSubscriberIntegration:
    """Clearance1 signal → notification → action → resolve flow on a real bus."""

    async def test_request_received_creates_notification(
        self, clearance_service: MockClearance1, subscriber_bus: MessageBus
    ):
        mock_notifier = AsyncMock()
        mock_notifier.notify = AsyncMock(return_value=1)
        mock_notifier.on_action = AsyncMock()

        sub = EventSubscriber(mock_notifier, bus=subscriber_bus)
        await sub.start()
        await asyncio.sleep(0.1)

        clearance_service.emit_request_received("req-10", PROJECT, TASK, DOMAIN, 443, REASON)
        await asyncio.sleep(0.2)

        mock_notifier.notify.assert_awaited_once()
        call = mock_notifier.notify.call_args
        assert TASK in call[0][0]
        assert f"{DOMAIN}:443" in call[0][0]
        assert ("accept", "Allow") in call.kwargs["actions"]
        assert ("deny", "Deny") in call.kwargs["actions"]
        assert call.kwargs["hints"]["urgency"].value == 2
        assert call.kwargs["hints"]["resident"].value is True
        assert call.kwargs["timeout_ms"] == 0
        await sub.stop()

    async def test_action_routes_resolve_to_service(
        self, clearance_service: MockClearance1, subscriber_bus: MessageBus
    ):
        mock_notifier = AsyncMock()
        mock_notifier.notify = AsyncMock(return_value=1)
        mock_notifier.on_action = AsyncMock()

        sub = EventSubscriber(mock_notifier, bus=subscriber_bus)
        await sub.start()
        await asyncio.sleep(0.1)

        clearance_service.emit_request_received("req-11", PROJECT, TASK, DOMAIN_ALT, 443, REASON)
        await asyncio.sleep(0.2)

        action_cb = mock_notifier.on_action.call_args[0][1]
        action_cb("deny")
        await asyncio.sleep(0.2)

        assert ("req-11", "deny") in clearance_service._resolve_log
        await sub.stop()

    async def test_request_resolved_updates_notification(
        self, clearance_service: MockClearance1, subscriber_bus: MessageBus
    ):
        mock_notifier = AsyncMock()
        mock_notifier.notify = AsyncMock(return_value=1)
        mock_notifier.on_action = AsyncMock()

        sub = EventSubscriber(mock_notifier, bus=subscriber_bus)
        await sub.start()
        await asyncio.sleep(0.1)

        clearance_service.emit_request_received("req-12", PROJECT, TASK, DOMAIN, 443, REASON)
        await asyncio.sleep(0.2)

        mock_notifier.notify.reset_mock()
        clearance_service.emit_request_resolved("req-12", "accept", [DEST_IP])
        await asyncio.sleep(0.2)

        mock_notifier.notify.assert_awaited_once()
        call = mock_notifier.notify.call_args
        assert call.kwargs["replaces_id"] == 1
        assert "Approved" in call[0][0]
        assert call.kwargs["hints"]["urgency"].value == 1
        await sub.stop()
