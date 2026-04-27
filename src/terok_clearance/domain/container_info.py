# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Container-inspection facts the clearance client cares about.

A minimal view over what ``podman inspect`` returns — enough for the
notifier / TUI subscriber to label an event.  Lives in the domain
layer because it's pure data; the thing that *produces* a
[`ContainerInfo`][terok_clearance.domain.container_info.ContainerInfo] lives at ``client/podman_inspector.py``.

Annotation semantics are caller-owned.  This module doesn't know
about ``ai.terok.*`` keys; whoever pulls a [`ContainerInfo`][terok_clearance.domain.container_info.ContainerInfo]
plucks the annotations it understands.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

#: Sentinel used as the default value for [`ContainerInfo.annotations`][terok_clearance.domain.container_info.ContainerInfo.annotations]
#: so every empty instance shares the same frozen mapping — prevents an
#: accidental write from leaking across callers.
_EMPTY_ANNOTATIONS: Mapping[str, str] = MappingProxyType({})


@dataclass(frozen=True)
class ContainerInfo:
    """What ``podman inspect`` tells us about one container.

    Empty instance (``ContainerInfo()``) represents "not found" or
    "lookup failed" — callers should treat missing fields as
    best-effort and fall back to the raw container ID when they
    don't have a better label.
    """

    container_id: str = ""
    """The short ID podman reported back, or empty on failure."""

    name: str = ""
    """The container's name without podman's leading ``/`` prefix."""

    state: str = ""
    """Lifecycle state: ``running``, ``exited``, ``created``, etc.  Empty when unknown."""

    annotations: Mapping[str, str] = field(default_factory=lambda: _EMPTY_ANNOTATIONS)
    """Every OCI annotation podman recorded for this container.

    Exposed as a read-only `Mapping` — cached instances are
    shared across inspector callers, so mutating the underlying dict
    would poison future lookups.  Build with [`types.MappingProxyType`][types.MappingProxyType]
    at construction time; callers (clearance's task-aware resolver,
    anything else that cares) pluck out the keys they know about.
    """
