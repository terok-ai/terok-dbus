# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Defensive sanitisation for strings flowing from containers to the desktop.

Dossier values originate inside the container's OCI annotations — i.e. an
attacker-controlled boundary — and end up interpolated into freedesktop
notification bodies that gnome-shell renders with limited markup support
(``<b>``, ``<i>``, ``<a href>``, ``<img src>``).  An unfiltered ``<img
src=javascript:…>`` or a multi-megabyte string would either reach the
session bus payload as-is or pop up as crafted-looking markup; both are
unacceptable on a security-alert surface.

Two filters apply, in order:

1. **Control-character squash** — ``\\n``, ``\\r``, ``\\t``, NULs, and any
   ``ord < 0x20`` byte become a single space so a single dossier value can't
   smuggle extra body lines into the popup.  Newlines that the renderer
   itself inserts between lines in [`_blocked_body`][terok_clearance.client.subscriber._blocked_body]
   stay intact — sanitisation operates on individual values, not whole bodies.
2. **Markup escape** — ``&``, ``<``, ``>`` are HTML-escaped so an attacker
   can't close the surrounding span and inject their own markup.  This is
   one-way: the popup shows literal ``&lt;script&gt;`` rather than
   rendering tags.  ``"`` and ``'`` are left alone — neither freedesktop's
   markup nor D-Bus hint values treat them specially.
3. **Length cap** — values longer than ``max_len`` (default 256) are
   truncated to ``max_len - 1`` chars and end with ``…`` so the popup
   stays readable.  256 fits the gnome-shell two-line body shape with
   plenty of headroom for normal task names.

The whole module is stdlib-only and intentionally short — sanitiser logic
is on the security boundary, so reading every line in one place is a
feature.
"""

from __future__ import annotations

#: Default per-value length cap.  Picked to comfortably exceed any
#: reasonable task or container name while staying inside the gnome-shell
#: two-line body shape.  Override per-call when a specific surface
#: (notification title vs. body line) wants something tighter.
DEFAULT_MAX_LEN = 256

#: ``ord`` boundary for the control-character squash.  Everything below
#: this — including all C0 controls (newline, tab, escape, …) — is
#: replaced with a space so a single dossier value can't smuggle extra
#: lines into the popup body.
_CONTROL_CHAR_BOUNDARY = 0x20

_MARKUP_ESCAPES = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
}


def sanitize(value: str, *, max_len: int = DEFAULT_MAX_LEN) -> str:
    """Return *value* safe for interpolation into a gnome-shell popup body.

    Control characters become spaces, markup-meaningful characters are
    HTML-escaped, and the result is length-capped.  ``""`` round-trips
    unchanged.

    Args:
        value: The raw string from a dossier field, an event payload, or
            anywhere else that crossed the container/host boundary.
        max_len: Truncate to this many characters.  The default
            ([`DEFAULT_MAX_LEN`][terok_clearance.notifications._sanitize.DEFAULT_MAX_LEN])
            is generous; tighter limits suit titles or compact labels.

    Returns:
        A sanitised string with the same character semantics as the
        input minus control bytes, with markup-special characters
        escaped, and capped at ``max_len`` (with a trailing ``…`` if
        truncation actually happened).
    """
    if not value:
        return ""
    cleaned_chars = (
        " " if ord(ch) < _CONTROL_CHAR_BOUNDARY else _MARKUP_ESCAPES.get(ch, ch) for ch in value
    )
    cleaned = "".join(cleaned_chars)
    if len(cleaned) > max_len:
        # Reserve one character for the ellipsis so the cap is a hard ceiling.
        return cleaned[: max_len - 1] + "…"
    return cleaned


def sanitize_mapping(mapping: dict[str, str], *, max_len: int = DEFAULT_MAX_LEN) -> dict[str, str]:
    """Apply [`sanitize`][terok_clearance.notifications._sanitize.sanitize] to every value in *mapping*.

    Keys flow through unchanged — they're internal identifiers (``project``,
    ``task``, ``name``, …), not user-visible strings, and the sanitiser is
    deliberately lenient on the key side so a typo'd annotation key still
    surfaces somewhere a human can spot it during debugging.
    """
    return {k: sanitize(v, max_len=max_len) for k, v in mapping.items()}
