# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Shield1 hub service."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from dbus_fast import RequestNameReply

from terok_dbus import _serve
from terok_dbus._interfaces import SHIELD_INTERFACE_NAME
from terok_dbus._serve import ShieldHub, _run_shield_cli, serve


class TestShieldHub:
    """Instantiation must register under the canonical Shield1 interface name."""

    def test_registered_interface_name(self) -> None:
        hub = ShieldHub()
        assert hub.name == SHIELD_INTERFACE_NAME


class TestServeRequestName:
    """``serve`` must refuse to start when another owner already holds the name."""

    @pytest.mark.asyncio
    async def test_not_primary_owner_raises(self) -> None:
        """IN_QUEUE / EXISTS / any non-PRIMARY reply is a hard error."""
        fake_bus = MagicMock()
        fake_bus.request_name = AsyncMock(return_value=RequestNameReply.IN_QUEUE)
        fake_bus.export = MagicMock()
        fake_bus.disconnect = MagicMock()
        with (
            patch.object(_serve, "MessageBus") as bus_cls,
            patch.object(_serve, "ShieldHub"),
            patch.object(_serve, "_desktop_notifier", AsyncMock()),
            patch.object(_serve, "EventSubscriber"),
            patch.object(_serve, "EventIngester"),
        ):
            bus_cls.return_value.connect = AsyncMock(return_value=fake_bus)
            with pytest.raises(RuntimeError, match="could not claim"):
                await serve()
        fake_bus.disconnect.assert_called_once()


class TestRunShieldCli:
    """``_run_shield_cli`` is the single place that touches the terok-shield binary."""

    @pytest.mark.asyncio
    async def test_allow_invokes_shield_with_ip(self) -> None:
        proc = AsyncMock()
        proc.communicate = AsyncMock(return_value=(b"", b""))
        proc.returncode = 0
        with (
            patch.object(_serve.shutil, "which", return_value="/bin/terok-shield"),
            patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)) as exec_mock,
        ):
            ok = await _run_shield_cli("c1", "10.0.0.5", "allow")
        assert ok is True
        cmd = exec_mock.await_args[0]
        assert cmd[1:] == ("allow", "c1", "10.0.0.5")

    @pytest.mark.asyncio
    async def test_deny_invokes_shield_deny(self) -> None:
        proc = AsyncMock()
        proc.communicate = AsyncMock(return_value=(b"", b""))
        proc.returncode = 0
        with (
            patch.object(_serve.shutil, "which", return_value="/bin/terok-shield"),
            patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)) as exec_mock,
        ):
            ok = await _run_shield_cli("c1", "10.0.0.5", "deny")
        assert ok is True
        assert exec_mock.await_args[0][1] == "deny"

    @pytest.mark.asyncio
    async def test_unknown_action_is_refused(self) -> None:
        with patch("asyncio.create_subprocess_exec") as exec_mock:
            ok = await _run_shield_cli("c1", "10.0.0.5", "maybe")
        assert ok is False
        exec_mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_missing_dest_is_refused(self) -> None:
        with patch("asyncio.create_subprocess_exec") as exec_mock:
            ok = await _run_shield_cli("c1", "", "allow")
        assert ok is False
        exec_mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_missing_shield_binary_is_refused(self) -> None:
        with (
            patch.object(_serve.shutil, "which", return_value=None),
            patch("asyncio.create_subprocess_exec") as exec_mock,
        ):
            ok = await _run_shield_cli("c1", "10.0.0.5", "allow")
        assert ok is False
        exec_mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_nonzero_exit_returns_false(self) -> None:
        proc = AsyncMock()
        proc.communicate = AsyncMock(return_value=(b"", b"nope\n"))
        proc.returncode = 2
        with (
            patch.object(_serve.shutil, "which", return_value="/bin/terok-shield"),
            patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)),
        ):
            ok = await _run_shield_cli("c1", "10.0.0.5", "allow")
        assert ok is False

    @pytest.mark.asyncio
    async def test_spawn_oserror_returns_false_clean(self) -> None:
        with (
            patch.object(_serve.shutil, "which", return_value="/bin/terok-shield"),
            patch(
                "asyncio.create_subprocess_exec",
                AsyncMock(side_effect=OSError("exec failed")),
            ),
        ):
            ok = await _run_shield_cli("c1", "10.0.0.5", "allow")
        assert ok is False

    @pytest.mark.asyncio
    async def test_subprocess_timeout_kills_and_returns_false(self) -> None:
        proc = AsyncMock()
        proc.communicate = AsyncMock(side_effect=TimeoutError)
        proc.kill = MagicMock()
        with (
            patch.object(_serve.shutil, "which", return_value="/bin/terok-shield"),
            patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)),
            patch("asyncio.wait_for", AsyncMock(side_effect=TimeoutError)),
        ):
            ok = await _run_shield_cli("c1", "10.0.0.5", "allow")
        assert ok is False
        proc.kill.assert_called_once()


class TestMakeEventSink:
    """The sink factory dispatches ingester JSON events onto hub signal methods."""

    @pytest.mark.asyncio
    async def test_pending_calls_connection_blocked(self) -> None:
        hub = MagicMock()
        sink = _serve._make_event_sink(hub)
        await sink(
            {
                "type": "pending",
                "container": "c1",
                "id": "c1:1",
                "dest": "10.0.0.5",
                "port": "443",
                "proto": "6",
                "domain": "example.com",
            }
        )
        hub.ConnectionBlocked.assert_called_once_with(
            "c1", "c1:1", "10.0.0.5", 443, 6, "example.com"
        )

    @pytest.mark.asyncio
    async def test_container_started_calls_hub(self) -> None:
        hub = MagicMock()
        sink = _serve._make_event_sink(hub)
        await sink({"type": "container_started", "container": "c1"})
        hub.ContainerStarted.assert_called_once_with("c1")

    @pytest.mark.asyncio
    async def test_container_exited_carries_reason(self) -> None:
        hub = MagicMock()
        sink = _serve._make_event_sink(hub)
        await sink({"type": "container_exited", "container": "c1", "reason": "poststop"})
        hub.ContainerExited.assert_called_once_with("c1", "poststop")

    @pytest.mark.asyncio
    async def test_missing_domain_defaults_to_empty_string(self) -> None:
        hub = MagicMock()
        sink = _serve._make_event_sink(hub)
        await sink(
            {
                "type": "pending",
                "container": "c1",
                "id": "c1:1",
                "dest": "10.0.0.5",
                "port": 443,
                "proto": 6,
            }
        )
        hub.ConnectionBlocked.assert_called_once_with("c1", "c1:1", "10.0.0.5", 443, 6, "")

    @pytest.mark.asyncio
    async def test_unknown_type_is_silent_noop(self) -> None:
        hub = MagicMock()
        sink = _serve._make_event_sink(hub)
        await sink({"type": "whatever", "payload": 1})
        hub.ConnectionBlocked.assert_not_called()
        hub.ContainerStarted.assert_not_called()
        hub.ContainerExited.assert_not_called()


class TestCleanupWithTimeout:
    """``_cleanup_with_timeout`` runs each stop step under a bounded timeout."""

    @pytest.mark.asyncio
    async def test_all_steps_finish_cleanly(self) -> None:
        ingester = MagicMock()
        subscriber = MagicMock()
        notifier = MagicMock()
        bus = MagicMock()
        ingester.stop = AsyncMock()
        subscriber.stop = AsyncMock()
        notifier.disconnect = AsyncMock()
        await _serve._cleanup_with_timeout(ingester, subscriber, notifier, bus)
        bus.disconnect.assert_called_once()

    @pytest.mark.asyncio
    async def test_hung_step_is_bounded_and_next_step_still_runs(self) -> None:
        ingester = MagicMock()
        subscriber = MagicMock()
        notifier = MagicMock()
        bus = MagicMock()
        ingester.stop = AsyncMock(side_effect=TimeoutError)
        subscriber.stop = AsyncMock()
        notifier.disconnect = AsyncMock()
        with patch("asyncio.wait_for", AsyncMock(side_effect=[TimeoutError, None, None])):
            await _serve._cleanup_with_timeout(ingester, subscriber, notifier, bus)
        bus.disconnect.assert_called_once()


class TestDesktopNotifier:
    """The hub prefers a real D-Bus notifier; falls back to null on headless hosts."""

    @pytest.mark.asyncio
    async def test_returns_dbus_notifier_when_bus_reachable(self) -> None:
        with patch.object(_serve, "DbusNotifier") as cls:
            instance = cls.return_value
            instance.connect = AsyncMock()
            notifier = await _serve._desktop_notifier()
            assert notifier is instance

    @pytest.mark.asyncio
    async def test_returns_null_notifier_on_failure(self) -> None:
        with (
            patch.object(_serve, "DbusNotifier") as cls,
            patch.object(_serve, "NullNotifier") as null_cls,
        ):
            cls.return_value.connect = AsyncMock(side_effect=OSError("no bus"))
            notifier = await _serve._desktop_notifier()
            assert notifier is null_cls.return_value

    @pytest.mark.asyncio
    async def test_returns_null_notifier_on_timeout(self) -> None:
        """A bus that accepts the connect but never answers falls back cleanly."""
        with (
            patch.object(_serve, "DbusNotifier") as cls,
            patch.object(_serve, "NullNotifier") as null_cls,
            patch("asyncio.wait_for", AsyncMock(side_effect=TimeoutError)),
        ):
            cls.return_value.connect = AsyncMock()
            notifier = await _serve._desktop_notifier()
            assert notifier is null_cls.return_value


class TestVerdictMethodDispatch:
    """``ShieldHub.Verdict`` shells out then emits VerdictApplied regardless of outcome."""

    @pytest.mark.asyncio
    async def test_verdict_emits_applied_on_success(self) -> None:
        hub = ShieldHub()
        emitted: list[tuple] = []
        hub.VerdictApplied = MagicMock(side_effect=lambda *args: emitted.append(args))
        with patch.object(_serve, "_run_shield_cli", AsyncMock(return_value=True)):
            ok = await hub._apply_verdict("c1", "c1:1", "10.0.0.5", "allow")
        assert ok is True
        assert emitted == [("c1", "c1:1", "allow", True)]

    @pytest.mark.asyncio
    async def test_verdict_still_emits_applied_on_failure(self) -> None:
        hub = ShieldHub()
        emitted: list[tuple] = []
        hub.VerdictApplied = MagicMock(side_effect=lambda *args: emitted.append(args))
        with patch.object(_serve, "_run_shield_cli", AsyncMock(return_value=False)):
            ok = await hub._apply_verdict("c1", "c1:1", "10.0.0.5", "allow")
        assert ok is False
        assert emitted == [("c1", "c1:1", "allow", False)]
