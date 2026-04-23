# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for :func:`run_shield` — the ``terok-shield`` subprocess wrapper."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from terok_clearance.verdict.shield_exec import run_shield

from .conftest import CONTAINER, DOMAIN


@pytest.mark.asyncio
async def test_missing_shield_binary() -> None:
    """``None`` binary path short-circuits to ``(False, reason)``."""
    ok, msg = await run_shield(None, CONTAINER, DOMAIN, "allow")
    assert ok is False
    assert "terok-shield" in msg


@pytest.mark.asyncio
async def test_success_returns_ok() -> None:
    proc = AsyncMock()
    proc.communicate = AsyncMock(return_value=(b"", b""))
    proc.returncode = 0
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
        ok, msg = await run_shield("/bin/true", CONTAINER, DOMAIN, "allow")
    assert ok is True
    assert msg == ""


@pytest.mark.asyncio
async def test_nonzero_exit_returns_stderr_snippet() -> None:
    proc = AsyncMock()
    proc.communicate = AsyncMock(return_value=(b"", b"boom\n"))
    proc.returncode = 1
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
        ok, msg = await run_shield("/bin/true", CONTAINER, DOMAIN, "allow")
    assert ok is False
    assert msg == "boom"


@pytest.mark.asyncio
async def test_timeout_kills_process() -> None:
    proc = AsyncMock()
    proc.communicate = AsyncMock(side_effect=TimeoutError)
    proc.kill = MagicMock()
    with (
        patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)),
        patch("asyncio.wait_for", AsyncMock(side_effect=TimeoutError)),
    ):
        ok, msg = await run_shield("/bin/true", CONTAINER, DOMAIN, "allow")
    assert ok is False
    assert "timed out" in msg
    proc.kill.assert_called_once()


@pytest.mark.asyncio
async def test_spawn_oserror_soft_fails() -> None:
    with patch(
        "asyncio.create_subprocess_exec",
        AsyncMock(side_effect=OSError("exec failed")),
    ):
        ok, msg = await run_shield("/bin/true", CONTAINER, DOMAIN, "allow")
    assert ok is False
    assert "spawn failed" in msg
