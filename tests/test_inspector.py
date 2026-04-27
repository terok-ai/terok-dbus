# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for [`terok_clearance.domain.inspector`][terok_clearance.domain.inspector].

Covers the runtime-neutral abstraction: the [`ContainerInspector`][terok_clearance.ContainerInspector]
protocol's structural check and the [`NullInspector`][terok_clearance.NullInspector] always-empty
default.
"""

from __future__ import annotations

from terok_clearance.domain.container_info import ContainerInfo
from terok_clearance.domain.inspector import ContainerInspector, NullInspector


def test_null_inspector_returns_empty_info() -> None:
    """Every lookup returns the universal empty [`ContainerInfo`][terok_clearance.ContainerInfo]."""
    assert NullInspector()("anything") == ContainerInfo()


def test_null_inspector_is_reusable() -> None:
    """Same instance safely handles many lookups — no per-call state."""
    inspector = NullInspector()
    for cid in ("a", "b", "c"):
        assert inspector(cid) == ContainerInfo()


def test_null_inspector_satisfies_protocol() -> None:
    """Runtime-check: ``NullInspector`` ducks-in as a [`ContainerInspector`][terok_clearance.ContainerInspector]."""
    assert isinstance(NullInspector(), ContainerInspector)


def test_custom_callable_satisfies_protocol() -> None:
    """Any callable with the right shape satisfies the protocol — no inheritance needed."""

    def inspect(_container_id: str) -> ContainerInfo:
        return ContainerInfo()

    assert isinstance(inspect, ContainerInspector)
