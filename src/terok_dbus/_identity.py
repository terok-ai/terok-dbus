# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Identity a subscriber can render about the container behind a blocked event.

The D-Bus signal carries only the podman short ID; everything richer is
recovered host-side from podman annotations and — for the mutable
human-readable name — from terok's task metadata.  A
:class:`ContainerIdentity` bundles what's been resolved so the subscriber
can pick the right body shape (task triple vs. bare container name)
without juggling three separate resolver return values.

An empty instance means "nothing known, fall back to the container ID".
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ContainerIdentity:
    """Host-side facts about a container, as much as the resolver found.

    Terok-managed task containers carry ``project`` and ``task_id`` via
    OCI annotations set at ``podman run`` time; ``task_name`` is looked
    up live from terok's task metadata so a rename between block and
    verdict is reflected in the resolved popup.  Standalone containers
    produce an instance with only ``container_name`` set (or empty
    everywhere when ``podman inspect`` itself failed).
    """

    container_name: str = ""
    project: str = ""
    task_id: str = ""
    task_name: str = ""
