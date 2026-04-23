# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Turn a container id into a task-aware :class:`ContainerIdentity`.

Composes an injected :class:`ContainerInspector` (container name +
OCI annotations, produced by whichever runtime backend the caller
plugged in) with a data-contract YAML lookup to produce
notification-ready identities.  Clearance carries no Python-import
coupling to any orchestrator; the one that created the container
publishes a path annotation pointing at its own metadata file, and
the resolver reads ``.name`` from that file on each call.

.. rubric:: Annotation contract

Containers that want friendly task-name enrichment in clearance
notifications set three OCI annotations at container creation:

``ai.terok.project``
    Project identifier (required for task-aware labelling).

``ai.terok.task``
    Task identifier within the project.

``ai.terok.task_meta_path``
    Absolute path to a YAML file.  The resolver reads the ``name``
    field and uses it as the display name.  Missing / unreadable /
    malformed files fall back silently to the container id.

Rename during a container's lifetime is preserved: the annotation
carries the *path*, not the name, and the orchestrator updates the
YAML in place.  Each resolver call reads the current value.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from terok_clearance.domain.identity import ContainerIdentity
from terok_clearance.domain.inspector import ContainerInspector

_log = logging.getLogger(__name__)

#: OCI annotations the resolver consumes.  Any container that sets
#: all three gets a task-aware identity; any missing one degrades
#: gracefully (container-name-only, or empty).
ANNOTATION_PROJECT = "ai.terok.project"
ANNOTATION_TASK = "ai.terok.task"
ANNOTATION_TASK_META_PATH = "ai.terok.task_meta_path"


class IdentityResolver:
    """Compose a :class:`ContainerInspector` lookup + task-meta YAML into an identity.

    Callable: ``resolver(container_id) -> ContainerIdentity``.  Four
    soft-fail paths, all returning a degraded identity that keeps the
    notification pipeline usable:

    * The inspector failed → empty :class:`ContainerIdentity`;
      the subscriber falls back to the raw container ID.
    * Container carries no terok annotations (a standalone container
      that happened to hit the firewall) → container-name-only.
    * ``ai.terok.task_meta_path`` annotation absent → identity without
      ``task_name`` (project + task_id still present).
    * ``task_meta_path`` YAML unreadable / missing / malformed → same
      as above; the name field is left empty.
    """

    def __init__(self, inspector: ContainerInspector) -> None:
        """Configure the resolver with a :class:`ContainerInspector` implementation.

        The inspector is required (no default) so the caller owns the
        runtime-selection decision — clearance is runtime-neutral and
        must not reach for a specific backend itself.  The notifier
        entry point picks an appropriate implementation at startup
        (terok-sandbox's ``create_container_inspector`` when available,
        :class:`NullInspector` otherwise).
        """
        self._inspector = inspector

    def __call__(self, container_id: str) -> ContainerIdentity:
        """Return the task-aware identity for *container_id*."""
        try:
            info = self._inspector(container_id)
        except Exception:
            # The contract says inspectors soft-fail by returning an
            # empty ``ContainerInfo``, but a runtime-side race or an
            # unexpected error path in a third-party backend can still
            # raise.  Clamp it here so the caller (notifier / TUI)
            # never takes a crash from identity resolution.
            _log.debug("ContainerInspector raised for %s", container_id, exc_info=True)
            return ContainerIdentity()
        if not info.container_id:
            return ContainerIdentity()
        project = info.annotations.get(ANNOTATION_PROJECT, "")
        task_id = info.annotations.get(ANNOTATION_TASK, "")
        if not (project and task_id):
            return ContainerIdentity(container_name=info.name, project=project, task_id=task_id)
        meta_path = info.annotations.get(ANNOTATION_TASK_META_PATH, "")
        return ContainerIdentity(
            container_name=info.name,
            project=project,
            task_id=task_id,
            task_name=_read_task_name(meta_path) if meta_path else "",
        )


def _read_task_name(meta_path: str) -> str:
    """Return the ``name`` field from the YAML at *meta_path*, or ``""`` on any failure.

    Every error mode maps to an empty string so the caller keeps its
    fallback label:

    * Non-absolute path — the annotation contract requires an absolute
      path; a relative path is almost certainly a bug (notifier runs
      under systemd with a PID-scoped cwd the writer can't predict).
    * Missing file / permission denied (any :class:`OSError`).
    * Invalid UTF-8 (:class:`UnicodeDecodeError`) — the YAML spec
      assumes UTF-8; treat mojibake like any other unreadable file.
    * Malformed YAML (:class:`yaml.YAMLError`).
    * Missing ``name`` key or non-string value.
    """
    path = Path(meta_path)
    if not path.is_absolute():
        _log.debug("task_meta_path is not absolute, refusing: %s", meta_path)
        return ""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        _log.debug("task_meta_path unreadable: %s", meta_path)
        return ""
    try:
        doc: Any = yaml.safe_load(text)
    except yaml.YAMLError:
        _log.debug("task_meta_path malformed YAML: %s", meta_path, exc_info=True)
        return ""
    if not isinstance(doc, dict):
        return ""
    name = doc.get("name", "")
    return name if isinstance(name, str) else ""
