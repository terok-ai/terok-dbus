# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the dossier-string sanitiser at the container → desktop boundary."""

from __future__ import annotations

import pytest

from terok_clearance.notifications._sanitize import (
    DEFAULT_MAX_LEN,
    sanitize,
    sanitize_mapping,
)


class TestSanitize:
    """``sanitize`` covers the three filters in order: control chars, markup, length."""

    def test_empty_string_round_trips(self) -> None:
        assert sanitize("") == ""

    def test_plain_ascii_unchanged(self) -> None:
        assert sanitize("alpine-7-redis") == "alpine-7-redis"

    def test_unicode_passes_through(self) -> None:
        """Non-ASCII letters/punctuation aren't markup-special — leave them alone."""
        assert sanitize("café · résumé") == "café · résumé"

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("a&b", "a&amp;b"),
            ("<script>", "&lt;script&gt;"),
            ("a < b > c", "a &lt; b &gt; c"),
            ("&amp;", "&amp;amp;"),  # double-escape is fine — display only
        ],
    )
    def test_markup_chars_are_escaped(self, raw: str, expected: str) -> None:
        assert sanitize(raw) == expected

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("line1\nline2", "line1 line2"),
            ("tab\there", "tab here"),
            ("car\rriage", "car riage"),
            ("null\x00byte", "null byte"),
            ("esc\x1bseq", "esc seq"),
        ],
    )
    def test_control_chars_become_spaces(self, raw: str, expected: str) -> None:
        assert sanitize(raw) == expected

    def test_xss_smuggling_via_markup_is_neutralised(self) -> None:
        """A crafted payload renders as literal text, not as markup."""
        payload = '<img src="javascript:alert(1)">'
        out = sanitize(payload)
        assert "<img" not in out
        assert "&lt;img" in out

    def test_length_cap_truncates_with_ellipsis(self) -> None:
        out = sanitize("x" * 1000, max_len=10)
        assert out == "xxxxxxxxx…"
        assert len(out) == 10

    def test_value_at_exact_cap_passes_through(self) -> None:
        out = sanitize("x" * 10, max_len=10)
        assert out == "x" * 10
        assert "…" not in out

    def test_default_max_len_is_generous(self) -> None:
        """Realistic dossier values stay full-fidelity."""
        name = "warp-core/t42-feature-rebuild-2026-04"
        assert len(name) < DEFAULT_MAX_LEN
        assert sanitize(name) == name

    def test_combination_of_all_three_filters(self) -> None:
        """Markup + control + length all apply when the input triggers each."""
        raw = "<bad>\nname\t" + "x" * 1000
        out = sanitize(raw, max_len=20)
        # No raw markup, no raw control bytes, length capped at 20.
        assert "<" not in out
        assert "\n" not in out
        assert "\t" not in out
        assert len(out) == 20
        assert out.endswith("…")


class TestSanitizeMapping:
    """``sanitize_mapping`` applies sanitisation to every value in a dict."""

    def test_sanitises_values_only(self) -> None:
        out = sanitize_mapping({"task": "<a>", "name": "b\nc"})
        assert out == {"task": "&lt;a&gt;", "name": "b c"}

    def test_keys_pass_through_unchanged(self) -> None:
        """Keys are internal identifiers — sanitiser is lenient on them."""
        out = sanitize_mapping({"<weird>": "v"})
        assert "<weird>" in out

    def test_empty_dict_round_trips(self) -> None:
        assert sanitize_mapping({}) == {}

    def test_max_len_threads_through(self) -> None:
        out = sanitize_mapping({"k": "x" * 1000}, max_len=5)
        assert out["k"] == "xxxx…"
