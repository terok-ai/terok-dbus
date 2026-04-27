# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Canonical verdict-helper socket path.

Separate tiny module so both ends (helper server + hub client) share
one literal.  The actual socket-hardening helpers live in
[`terok_clearance.wire.socket`][terok_clearance.wire.socket]; this module just names where
to meet.
"""

from pathlib import Path

from terok_clearance.wire.socket import runtime_socket_path

#: Canonical verdict-helper socket basename under ``$XDG_RUNTIME_DIR``.
_VERDICT_SOCKET_BASENAME = "terok-clearance-verdict.sock"


def default_verdict_socket_path() -> Path:
    """Return the canonical verdict-helper socket path under ``$XDG_RUNTIME_DIR``."""
    return runtime_socket_path(_VERDICT_SOCKET_BASENAME)
