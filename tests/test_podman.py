# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the podman-backed identity resolver."""

from __future__ import annotations

import json
import subprocess
from unittest import mock

from terok_dbus._identity import ContainerIdentity
from terok_dbus._podman import PodmanIdentityResolver


def _fake_proc(returncode: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    """Shape one ``subprocess.run`` result for the resolver to consume."""
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _inspect_json(
    *,
    name: str = "my-task",
    project: str = "",
    task_id: str = "",
) -> str:
    """Render a podman-inspect JSON payload with optional terok annotations."""
    annotations: dict[str, str] = {}
    if project:
        annotations["ai.terok.project"] = project
    if task_id:
        annotations["ai.terok.task"] = task_id
    record: dict[str, object] = {"Name": f"/{name}", "Config": {"Annotations": annotations}}
    return json.dumps([record])


class TestPodmanIdentityResolver:
    """Resolver extracts name + terok annotations, caches, soft-fails."""

    def test_returns_name_when_no_annotations(self) -> None:
        """Standalone containers surface as name-only identities."""
        with (
            mock.patch("terok_dbus._podman.shutil.which", return_value="/usr/bin/podman"),
            mock.patch(
                "terok_dbus._podman.subprocess.run",
                return_value=_fake_proc(0, stdout=_inspect_json(name="my-task")),
            ),
        ):
            resolver = PodmanIdentityResolver()
            identity = resolver("abc123")
        assert identity == ContainerIdentity(container_name="my-task")

    def test_returns_full_identity_when_annotations_present(self) -> None:
        """Terok-managed containers surface as (name, project, task_id)."""
        with (
            mock.patch("terok_dbus._podman.shutil.which", return_value="/usr/bin/podman"),
            mock.patch(
                "terok_dbus._podman.subprocess.run",
                return_value=_fake_proc(
                    0,
                    stdout=_inspect_json(
                        name="alpaka3-cli-z71dr", project="alpaka3", task_id="z71dr"
                    ),
                ),
            ),
        ):
            identity = PodmanIdentityResolver()("abc123")
        assert identity == ContainerIdentity(
            container_name="alpaka3-cli-z71dr",
            project="alpaka3",
            task_id="z71dr",
        )
        assert identity.task_name == ""  # resolver never reads the YAML

    def test_empty_id_returns_empty_identity(self) -> None:
        """An empty container ID never reaches podman."""
        with mock.patch("terok_dbus._podman.subprocess.run") as run:
            assert PodmanIdentityResolver()("") == ContainerIdentity()
            run.assert_not_called()

    def test_caches_lookups(self) -> None:
        """Repeat calls for the same ID don't re-invoke podman."""
        with (
            mock.patch("terok_dbus._podman.shutil.which", return_value="/usr/bin/podman"),
            mock.patch(
                "terok_dbus._podman.subprocess.run",
                return_value=_fake_proc(0, stdout=_inspect_json(name="my-task")),
            ) as run,
        ):
            resolver = PodmanIdentityResolver()
            first = resolver("abc123")
            second = resolver("abc123")
            assert first == second
            assert run.call_count == 1

    def test_returns_empty_when_podman_missing(self) -> None:
        """No podman on PATH → empty identity, caller falls back to the ID."""
        with mock.patch("terok_dbus._podman.shutil.which", return_value=None):
            assert PodmanIdentityResolver()("abc123") == ContainerIdentity()

    def test_returns_empty_on_inspect_nonzero(self) -> None:
        """podman inspect failure (unknown ID) → empty identity."""
        with (
            mock.patch("terok_dbus._podman.shutil.which", return_value="/usr/bin/podman"),
            mock.patch(
                "terok_dbus._podman.subprocess.run",
                return_value=_fake_proc(1, stderr="no such container"),
            ),
        ):
            assert PodmanIdentityResolver()("abc123") == ContainerIdentity()

    def test_returns_empty_on_malformed_json(self) -> None:
        """A podman that returns non-JSON output doesn't crash the resolver."""
        with (
            mock.patch("terok_dbus._podman.shutil.which", return_value="/usr/bin/podman"),
            mock.patch(
                "terok_dbus._podman.subprocess.run",
                return_value=_fake_proc(0, stdout="not-json"),
            ),
        ):
            assert PodmanIdentityResolver()("abc123") == ContainerIdentity()

    def test_returns_empty_on_timeout(self) -> None:
        """podman hung → empty identity."""
        with (
            mock.patch("terok_dbus._podman.shutil.which", return_value="/usr/bin/podman"),
            mock.patch(
                "terok_dbus._podman.subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd="podman", timeout=5),
            ),
        ):
            assert PodmanIdentityResolver()("abc123") == ContainerIdentity()

    def test_returns_empty_on_oserror(self) -> None:
        """Subprocess raises OSError (e.g. binary missing mid-run) → empty identity."""
        with (
            mock.patch("terok_dbus._podman.shutil.which", return_value="/usr/bin/podman"),
            mock.patch("terok_dbus._podman.subprocess.run", side_effect=OSError("no such file")),
        ):
            assert PodmanIdentityResolver()("abc123") == ContainerIdentity()

    def test_argv_uses_dash_dash_separator(self) -> None:
        """``--`` precedes the container argument to guard against leading-dash IDs."""
        with (
            mock.patch("terok_dbus._podman.shutil.which", return_value="/usr/bin/podman"),
            mock.patch(
                "terok_dbus._podman.subprocess.run",
                return_value=_fake_proc(0, stdout=_inspect_json(name="t")),
            ) as run,
        ):
            PodmanIdentityResolver()("abc123")
        argv = run.call_args.args[0]
        assert "--" in argv
        assert argv.index("abc123") > argv.index("--")

    def test_strips_podman_name_prefix(self) -> None:
        """Podman prefixes ``.Name`` with a leading slash; the resolver drops it."""
        with (
            mock.patch("terok_dbus._podman.shutil.which", return_value="/usr/bin/podman"),
            mock.patch(
                "terok_dbus._podman.subprocess.run",
                return_value=_fake_proc(0, stdout=_inspect_json(name="my-task")),
            ),
        ):
            identity = PodmanIdentityResolver()("abc123")
        assert identity.container_name == "my-task"
