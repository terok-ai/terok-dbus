# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Fixtures and skip guards for integration tests.

Environment requirements are expressed via pytest markers:

- ``needs_dbus``: a D-Bus session bus must be reachable.
- ``needs_notification_daemon``: a notification daemon (dunst) must be
  running on the session bus.

The ``dbus_session`` and ``notification_daemon`` fixtures spin up a
private bus and dunst when none is available, so the tests are
self-contained in both CI and the matrix runner containers.
"""

import os
import shutil
import signal
import subprocess
import time
from collections.abc import AsyncIterator, Iterator

import pytest

from terok_dbus import DbusNotifier, Notifier, create_notifier


def _has(binary: str) -> bool:
    """Check if a binary is available on PATH."""
    return shutil.which(binary) is not None


dbus_daemon_missing = pytest.mark.skipif(
    not _has("dbus-launch"), reason="dbus-launch not installed"
)
dunst_missing = pytest.mark.skipif(not _has("dunst"), reason="dunst not installed")


@pytest.fixture(scope="session")
def dbus_session() -> Iterator[str]:
    """Start a private D-Bus session bus for the test run.

    If ``DBUS_SESSION_BUS_ADDRESS`` is already set and reachable,
    reuse it.  Otherwise launch a fresh ``dbus-daemon --session``.

    Yields:
        The bus address string.
    """
    existing = os.environ.get("DBUS_SESSION_BUS_ADDRESS")
    if existing:
        yield existing
        return

    if not _has("dbus-launch"):
        pytest.skip("dbus-launch not installed")

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
    """Start dunst on the session bus if not already running.

    Yields once dunst is ready to accept notifications.
    """
    if not _has("dunst"):
        pytest.skip("dunst not installed")

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
