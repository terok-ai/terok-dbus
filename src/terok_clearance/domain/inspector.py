# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Runtime-neutral container introspection abstraction.

Clearance renders notifications for every container the firewall
touches, regardless of which runtime created it (podman today; a
future krun / docker / containerd backend tomorrow).  The translation
from *container id* to [`ContainerInfo`][terok_clearance.ContainerInfo] is therefore expressed
here as a pure [`ContainerInspector`][terok_clearance.domain.inspector.ContainerInspector] protocol; the concrete
backend that knows how to talk to a specific runtime lives in
terok-sandbox, where runtime selection is owned.

[`NullInspector`][terok_clearance.domain.inspector.NullInspector] ships as a safe default: deployments without
any runtime-aware package installed (clearance standalone, test
rigs) still boot; notifications just carry raw container ids.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from terok_clearance.domain.container_info import ContainerInfo


@runtime_checkable
class ContainerInspector(Protocol):
    """Callable that maps a container id to a [`ContainerInfo`][terok_clearance.ContainerInfo].

    The protocol intentionally covers only the notification-rendering
    use case — name + OCI annotations + lifecycle state.  Broader
    runtime operations (exec, mount, signals) live on
    ``terok_sandbox.runtime.ContainerRuntime`` and are not part of
    this contract.

    Implementations MUST soft-fail: an unreachable runtime / missing
    container / malformed metadata returns an empty [`ContainerInfo`][terok_clearance.ContainerInfo]
    rather than raising, so notification pipelines keep their fallback
    label instead of crashing on a lookup hiccup.
    """

    def __call__(self, container_id: str) -> ContainerInfo:
        """Return the best-effort [`ContainerInfo`][terok_clearance.ContainerInfo] for *container_id*."""
        ...


class NullInspector:
    """Always-empty [`ContainerInspector`][terok_clearance.domain.inspector.ContainerInspector] — the graceful-degradation default.

    Installed when no runtime-aware package provides a concrete
    backend.  Every lookup returns ``ContainerInfo()`` so the
    notifier still renders (raw container id, no enrichment).
    """

    def __call__(self, _container_id: str) -> ContainerInfo:
        """Return the universal empty [`ContainerInfo`][terok_clearance.ContainerInfo]."""
        return ContainerInfo()
