# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shared test fixtures and constants for terok-dbus."""

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
