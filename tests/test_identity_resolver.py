# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for :mod:`terok_clearance.client.identity_resolver`.

Annotation data-contract coverage — the notifier must render the
live task name for any container that publishes
``ai.terok.task_meta_path``, and must fall back to container-id when
the path is missing or unreadable.
"""

from __future__ import annotations

from pathlib import Path
from types import MappingProxyType
from unittest.mock import MagicMock

from terok_clearance.client.identity_resolver import (
    ANNOTATION_PROJECT,
    ANNOTATION_TASK,
    ANNOTATION_TASK_META_PATH,
    IdentityResolver,
)
from terok_clearance.domain.container_info import ContainerInfo
from terok_clearance.domain.inspector import NullInspector


def _fake_inspector(info: ContainerInfo) -> MagicMock:
    """Return a callable that behaves like :class:`PodmanInspector` but yields *info*."""
    mock = MagicMock()
    mock.return_value = info
    return mock


def _info(
    *, name: str = "c", project: str = "", task: str = "", meta_path: str = ""
) -> ContainerInfo:
    """Build a :class:`ContainerInfo` with the three terok annotations populated."""
    annotations: dict[str, str] = {}
    if project:
        annotations[ANNOTATION_PROJECT] = project
    if task:
        annotations[ANNOTATION_TASK] = task
    if meta_path:
        annotations[ANNOTATION_TASK_META_PATH] = meta_path
    return ContainerInfo(container_id=name, name=name, annotations=MappingProxyType(annotations))


class TestSoftFailPaths:
    """Four soft-fail paths — each returns a usable degraded identity."""

    def test_inspector_raises_returns_empty(self) -> None:
        inspector = MagicMock(side_effect=RuntimeError("podman crashed"))
        identity = IdentityResolver(inspector=inspector)("some-id")
        assert identity.container_name == ""
        assert identity.task_name == ""

    def test_missing_container_returns_empty(self) -> None:
        inspector = _fake_inspector(ContainerInfo())
        identity = IdentityResolver(inspector=inspector)("missing-id")
        assert identity.container_name == ""

    def test_no_terok_annotations_name_only(self) -> None:
        """Standalone container (no project/task annotations) → container-name-only identity."""
        inspector = _fake_inspector(_info(name="stray"))
        identity = IdentityResolver(inspector=inspector)("stray")
        assert identity.container_name == "stray"
        assert identity.project == ""
        assert identity.task_id == ""
        assert identity.task_name == ""

    def test_annotations_but_no_meta_path_leaves_task_name_empty(self) -> None:
        """Project + task present but no meta-path → enriched identity sans task_name."""
        inspector = _fake_inspector(_info(name="c", project="p", task="t"))
        identity = IdentityResolver(inspector=inspector)("c")
        assert identity.project == "p"
        assert identity.task_id == "t"
        assert identity.task_name == ""


class TestTaskMetaPathContract:
    """YAML sidecar lookup — the data contract the notifier depends on."""

    def test_reads_name_from_yaml(self, tmp_path: Path) -> None:
        meta = tmp_path / "task.yml"
        meta.write_text("name: Refactor the auth module\ntask_id: abc\n", encoding="utf-8")
        inspector = _fake_inspector(
            _info(name="c", project="my-proj", task="abc", meta_path=str(meta))
        )
        identity = IdentityResolver(inspector=inspector)("c")
        assert identity.task_name == "Refactor the auth module"

    def test_missing_file_falls_back(self, tmp_path: Path) -> None:
        """Annotation points at a path that doesn't exist → soft-fail."""
        inspector = _fake_inspector(
            _info(name="c", project="p", task="t", meta_path=str(tmp_path / "does-not-exist.yml"))
        )
        identity = IdentityResolver(inspector=inspector)("c")
        assert identity.task_name == ""
        # Everything else still populated so the notifier has a useful label:
        assert identity.project == "p"
        assert identity.task_id == "t"

    def test_malformed_yaml_falls_back(self, tmp_path: Path) -> None:
        meta = tmp_path / "broken.yml"
        meta.write_text("name: [unterminated", encoding="utf-8")
        inspector = _fake_inspector(_info(name="c", project="p", task="t", meta_path=str(meta)))
        identity = IdentityResolver(inspector=inspector)("c")
        assert identity.task_name == ""

    def test_missing_name_key_falls_back(self, tmp_path: Path) -> None:
        meta = tmp_path / "nameless.yml"
        meta.write_text("task_id: abc\nworkspace: /w\n", encoding="utf-8")
        inspector = _fake_inspector(_info(name="c", project="p", task="t", meta_path=str(meta)))
        identity = IdentityResolver(inspector=inspector)("c")
        assert identity.task_name == ""

    def test_non_string_name_falls_back(self, tmp_path: Path) -> None:
        """A non-string ``name`` (e.g. someone wrote a list) → empty, not a crash."""
        meta = tmp_path / "weird.yml"
        meta.write_text("name:\n  - a\n  - b\n", encoding="utf-8")
        inspector = _fake_inspector(_info(name="c", project="p", task="t", meta_path=str(meta)))
        identity = IdentityResolver(inspector=inspector)("c")
        assert identity.task_name == ""

    def test_relative_meta_path_refused(self, tmp_path: Path) -> None:
        """Annotation contract requires an absolute path; a relative one is refused."""
        meta = tmp_path / "task.yml"
        meta.write_text("name: ignored\n", encoding="utf-8")
        # Pass the bare filename, not the absolute path — shouldn't be read.
        inspector = _fake_inspector(_info(name="c", project="p", task="t", meta_path="task.yml"))
        identity = IdentityResolver(inspector=inspector)("c")
        assert identity.task_name == ""

    def test_invalid_utf8_falls_back(self, tmp_path: Path) -> None:
        """Non-UTF8 bytes in the YAML file → soft-fail, not a :class:`UnicodeDecodeError`."""
        meta = tmp_path / "mojibake.yml"
        meta.write_bytes(b"name: \xff\xfe\xfa\n")
        inspector = _fake_inspector(_info(name="c", project="p", task="t", meta_path=str(meta)))
        identity = IdentityResolver(inspector=inspector)("c")
        assert identity.task_name == ""

    def test_rename_visible_on_next_call(self, tmp_path: Path) -> None:
        """The whole point of the path-annotation: rename is live, not snapshot."""
        meta = tmp_path / "task.yml"
        meta.write_text("name: First\n", encoding="utf-8")
        inspector = _fake_inspector(_info(name="c", project="p", task="t", meta_path=str(meta)))
        resolver = IdentityResolver(inspector=inspector)

        assert resolver("c").task_name == "First"
        meta.write_text("name: Renamed\n", encoding="utf-8")
        assert resolver("c").task_name == "Renamed"


class TestNullInspectorIntegration:
    """:class:`NullInspector` is the graceful-degradation default for standalone hosts."""

    def test_null_inspector_drives_empty_identity(self) -> None:
        """No runtime-aware package installed → resolver returns empty identity."""
        identity = IdentityResolver(inspector=NullInspector())("anything")
        assert identity.container_name == ""
        assert identity.project == ""
        assert identity.task_name == ""
