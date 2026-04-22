# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Resolve short podman container IDs to a :class:`ContainerIdentity`.

Used by the hub to enrich notifications with the container name plus —
when terok's orchestrator launched the container — the project and
task IDs it annotated the container with.  The human-readable task
name is left for the caller to resolve from terok's task metadata
because it is mutable and lives outside the OCI world.

One ``podman inspect`` per container, cached per-process.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess  # nosec B404 — podman is a trusted host binary
from typing import Any

from terok_dbus._identity import ContainerIdentity

_log = logging.getLogger(__name__)

_INSPECT_TIMEOUT_S = 5

#: OCI annotations terok-orchestrator sets at ``podman run`` time so the
#: hub can tell a task container apart from a standalone one without
#: parsing the container name.
_ANNOTATION_PROJECT = "ai.terok.project"
_ANNOTATION_TASK = "ai.terok.task"


class PodmanIdentityResolver:
    """Cached ID → :class:`ContainerIdentity` lookup backed by ``podman inspect``.

    Callable: instances act as ``Callable[[str], ContainerIdentity]``.
    On miss, shells out to ``podman inspect --format=json`` and extracts
    ``.Name`` plus the ``ai.terok.project`` / ``ai.terok.task``
    annotations (empty strings for containers that carry neither,
    e.g. standalone executor runs).  Returns an empty identity on any
    failure so callers keep a usable fallback (the ID) in the rendered
    notification body.
    """

    def __init__(self) -> None:
        """Initialise with an empty cache."""
        self._cache: dict[str, ContainerIdentity] = {}

    def __call__(self, container_id: str) -> ContainerIdentity:
        """Return the container's identity, or an empty one on lookup failure."""
        if not container_id:
            return ContainerIdentity()
        if (cached := self._cache.get(container_id)) is not None:
            return cached
        identity = self._inspect(container_id)
        self._cache[container_id] = identity
        return identity

    @staticmethod
    def _inspect(container_id: str) -> ContainerIdentity:
        """Shell out to ``podman inspect`` once, with timeout + soft-fail."""
        podman = shutil.which("podman")
        if not podman:
            _log.debug("podman not on PATH — identity resolution unavailable")
            return ContainerIdentity()
        try:
            # ``--`` guards against a hostile *container_id* that starts with
            # a dash being interpreted as a podman flag.  Container IDs never
            # naturally start with a dash but the public surface accepts
            # whatever the bus delivers; be defensive at the boundary.
            result = subprocess.run(  # nosec B603
                [podman, "inspect", "--format=json", "--", container_id],
                check=False,
                capture_output=True,
                text=True,
                timeout=_INSPECT_TIMEOUT_S,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            _log.debug("podman inspect failed for %s: %s", container_id, exc)
            return ContainerIdentity()
        if result.returncode != 0:
            _log.debug(
                "podman inspect %s returned %d: %s",
                container_id,
                result.returncode,
                result.stderr.strip(),
            )
            return ContainerIdentity()
        try:
            records = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            _log.debug("podman inspect %s returned malformed JSON: %s", container_id, exc)
            return ContainerIdentity()
        return _from_inspect(records)


def _from_inspect(records: Any) -> ContainerIdentity:
    """Extract name + terok annotations from a ``podman inspect`` payload."""
    if not isinstance(records, list) or not records:
        return ContainerIdentity()
    head = records[0]
    if not isinstance(head, dict):
        return ContainerIdentity()
    name = head.get("Name") if isinstance(head.get("Name"), str) else ""
    config = head.get("Config") if isinstance(head.get("Config"), dict) else {}
    annotations = config.get("Annotations") if isinstance(config.get("Annotations"), dict) else {}
    project = annotations.get(_ANNOTATION_PROJECT, "") if isinstance(annotations, dict) else ""
    task_id = annotations.get(_ANNOTATION_TASK, "") if isinstance(annotations, dict) else ""
    return ContainerIdentity(
        container_name=name.lstrip("/"),  # podman prefixes names with '/'
        project=project if isinstance(project, str) else "",
        task_id=task_id if isinstance(task_id, str) else "",
    )
