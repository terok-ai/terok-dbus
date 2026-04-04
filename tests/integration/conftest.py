# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Fixtures and skip guards for integration tests.

Environment requirements are expressed via pytest markers:

- ``needs_dbus``: a D-Bus session bus must be reachable.
- ``needs_notification_daemon``: a notification daemon must be
  running on the session bus (existing or started by the fixture).

The ``dbus_session`` fixture reuses the existing session bus or
launches a private one via ``dbus-daemon``.  The ``notification_daemon``
fixture detects an already-running daemon before attempting to start
dunst — so tests work on a developer desktop (existing daemon) and in
CI/matrix containers (dunst started by fixture) alike.
"""

import asyncio
import os
import shutil
import signal
import subprocess
import time
from collections.abc import AsyncIterator, Iterator

import pytest

from terok_dbus import DbusNotifier, Notifier, create_notifier
from terok_dbus._constants import BUS_NAME, OBJECT_PATH


def _has(binary: str) -> bool:
    """Check if a binary is available on PATH."""
    return shutil.which(binary) is not None


def _daemon_on_bus(bus_address: str) -> bool:
    """Return True if a notification daemon is reachable on the bus."""
    from dbus_fast.aio import MessageBus

    async def _probe() -> bool:
        try:
            bus = await MessageBus(bus_address=bus_address).connect()
            try:
                await bus.introspect(BUS_NAME, OBJECT_PATH)
                return True
            except Exception:
                return False
            finally:
                bus.disconnect()
        except Exception:
            return False

    return asyncio.get_event_loop().run_until_complete(_probe())


@pytest.fixture(scope="session")
def dbus_session() -> Iterator[str]:
    """Provide a D-Bus session bus address for the test run.

    Reuses ``DBUS_SESSION_BUS_ADDRESS`` when set, otherwise launches
    a private ``dbus-daemon --session`` via ``dbus-launch``.

    Yields:
        The bus address string.
    """
    existing = os.environ.get("DBUS_SESSION_BUS_ADDRESS")
    if existing:
        yield existing
        return

    if not _has("dbus-launch"):
        pytest.skip("dbus-launch not installed and DBUS_SESSION_BUS_ADDRESS not set")

    proc = subprocess.run(
        ["dbus-launch", "--sh-syntax"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if proc.returncode != 0:
        pytest.skip(f"dbus-launch failed: {proc.stderr}")

    env = {}
    for line in proc.stdout.splitlines():
        if "=" in line:
            key, _, val = line.partition("=")
            env[key] = val.rstrip(";").strip("'")

    bus_address = env.get("DBUS_SESSION_BUS_ADDRESS", "")
    bus_pid = env.get("DBUS_SESSION_BUS_PID", "")

    if not bus_address:
        pytest.skip(f"dbus-launch did not provide DBUS_SESSION_BUS_ADDRESS: {proc.stdout!r}")

    os.environ["DBUS_SESSION_BUS_ADDRESS"] = bus_address

    yield bus_address

    os.environ.pop("DBUS_SESSION_BUS_ADDRESS", None)
    if bus_pid:
        try:
            os.kill(int(bus_pid), signal.SIGTERM)
        except (ProcessLookupError, ValueError):
            pass


@pytest.fixture(scope="session")
def notification_daemon(dbus_session: str) -> Iterator[None]:
    """Ensure a notification daemon is available on the session bus.

    If one is already running (desktop session), yield immediately.
    Otherwise start dunst and yield once it registers on the bus.
    Skips if neither is available.
    """
    if _daemon_on_bus(dbus_session):
        yield
        return

    if not _has("dunst"):
        pytest.skip(
            "no notification daemon on bus and dunst not installed; "
            "install dunst or run from a desktop session"
        )

    proc = subprocess.Popen(
        ["dunst"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={**os.environ, "DBUS_SESSION_BUS_ADDRESS": dbus_session},
    )
    time.sleep(0.5)

    if proc.poll() is not None:
        pytest.skip("dunst failed to start")

    yield

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture
async def notifier(dbus_session: str, notification_daemon: None) -> AsyncIterator[Notifier]:
    """Provide a connected ``DbusNotifier`` backed by the test bus.

    Disconnects automatically after the test.
    """
    n = await create_notifier()
    if not isinstance(n, DbusNotifier):
        pytest.skip("D-Bus notifier backend unavailable in integration environment")
    yield n
    await n.disconnect()
