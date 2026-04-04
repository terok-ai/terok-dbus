# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Story: CLI end-to-end.

The ``terok-dbus-notify`` command-line tool must send a real notification
and print its server-assigned ID, or print ``0`` when no bus is available.
"""

import os
import subprocess
import sys

import pytest

pytestmark = pytest.mark.needs_dbus


class TestCliIntegration:
    """End-to-end CLI tests against a real session bus."""

    def test_notify_prints_positive_id(self, dbusmock_session, notification_daemon):
        """CLI prints a positive integer notification ID."""
        result = subprocess.run(
            [sys.executable, "-m", "terok_dbus._cli", "CLI test", "Body text"],
            capture_output=True,
            text=True,
            timeout=10,
            env=os.environ,
        )
        assert result.returncode == 0, result.stderr
        nid = int(result.stdout.strip())
        assert nid > 0

    def test_timeout_flag_accepted(self, dbusmock_session, notification_daemon):
        """CLI accepts -t/--timeout and still produces a valid ID."""
        result = subprocess.run(
            [sys.executable, "-m", "terok_dbus._cli", "-t", "1000", "Timeout test"],
            capture_output=True,
            text=True,
            timeout=10,
            env=os.environ,
        )
        assert result.returncode == 0, result.stderr
        nid = int(result.stdout.strip())
        assert nid > 0

    def test_body_is_optional(self, dbusmock_session, notification_daemon):
        """CLI works with summary only (no body argument)."""
        result = subprocess.run(
            [sys.executable, "-m", "terok_dbus._cli", "Summary only"],
            capture_output=True,
            text=True,
            timeout=10,
            env=os.environ,
        )
        assert result.returncode == 0, result.stderr
        nid = int(result.stdout.strip())
        assert nid > 0
