# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shared test fixtures and constants for terok-dbus."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

# ── Test data constants ────────────────────────────────────────────────
# Reusable across unit and integration tests for subscriber scenarios.

DEST_IP = "198.51.100.1"
DEST_IP_ALT = "198.51.100.2"
RESOLVED_IPS = ["198.51.100.1", "198.51.100.2"]
DOMAIN = "registry.example.net"
DOMAIN_ALT = "repo.example.net"
CONTAINER = "sandbox-alpha"
PROJECT = "warp-core"
TASK = "build"
REASON = "install deps"


@pytest.fixture
def private_runtime_dir(tmp_path: Path) -> Iterator[Path]:
    """A mode-0700, uid-owned directory for ingester / clearance sockets.

    ``EventIngester`` and ``ClearanceHub`` both refuse to bind under a
    parent the current uid doesn't own or that's group/world accessible
    — the on-disk auth boundary.  ``tmp_path`` is usually fine, but some
    CI hosts use a shared tmpfs with bespoke modes.  This fixture forces
    the correct shape so socket-bind tests see a clean slate.
    """
    priv = tmp_path / "runtime"
    priv.mkdir(mode=0o700)
    os.chmod(priv, 0o700)
    yield priv
