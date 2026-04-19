# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Shield1 hub service."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from terok_dbus import _serve
from terok_dbus._interfaces import SHIELD_INTERFACE_NAME
from terok_dbus._serve import ShieldHub, _run_shield_cli


class TestShieldHub:
    """Instantiation must register under the canonical Shield1 interface name."""

    def test_registered_interface_name(self) -> None:
        hub = ShieldHub()
        assert hub.name == SHIELD_INTERFACE_NAME


class TestRunShieldCli:
    """``_run_shield_cli`` is the single place that touches the terok-shield binary."""

    @pytest.mark.asyncio
    async def test_allow_invokes_shield_with_ip(self) -> None:
        proc = AsyncMock()
        proc.wait = AsyncMock(return_value=0)
        proc.stderr = None
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
        proc.wait = AsyncMock(return_value=0)
        proc.stderr = None
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
        proc.wait = AsyncMock(return_value=2)
        proc.stderr = AsyncMock()
        proc.stderr.read = AsyncMock(return_value=b"nope\n")
        with (
            patch.object(_serve.shutil, "which", return_value="/bin/terok-shield"),
            patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)),
        ):
            ok = await _run_shield_cli("c1", "10.0.0.5", "allow")
        assert ok is False


class TestDesktopNotifier:
    """The hub prefers a real D-Bus notifier; falls back to null on headless hosts."""

    @pytest.mark.asyncio
    async def test_returns_dbus_notifier_when_bus_reachable(self) -> None:
        with patch.object(_serve, "DbusNotifier") as cls:
            instance = cls.return_value
            instance._connect = AsyncMock()
            notifier = await _serve._desktop_notifier()
            assert notifier is instance

    @pytest.mark.asyncio
    async def test_returns_null_notifier_on_failure(self) -> None:
        with (
            patch.object(_serve, "DbusNotifier") as cls,
            patch.object(_serve, "NullNotifier") as null_cls,
        ):
            cls.return_value._connect = AsyncMock(side_effect=OSError("no bus"))
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
