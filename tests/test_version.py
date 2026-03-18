# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Smoke test — verify the package is importable."""

import terok_dbus


def test_package_is_importable():
    """The terok_dbus package should be importable and expose __version__."""
    assert hasattr(terok_dbus, "__version__")
    assert isinstance(terok_dbus.__version__, str)
