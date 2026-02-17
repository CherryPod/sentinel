from sentinel.security.spotlighting import apply_datamarking, remove_datamarking


class TestApplyDatamarking:
    def test_single_word(self):
        assert apply_datamarking("hello") == "^hello"

    def test_multi_word(self):
        assert apply_datamarking("hello world") == "^hello ^world"

    def test_preserves_spaces(self):
        assert apply_datamarking("a  b") == "^a  ^b"

    def test_preserves_newlines(self):
        assert apply_datamarking("line1\nline2") == "^line1\n^line2"

    def test_preserves_tabs(self):
        assert apply_datamarking("col1\tcol2") == "^col1\t^col2"

    def test_empty_string(self):
        assert apply_datamarking("") == ""

    def test_punctuation_attached(self):
        assert apply_datamarking("hello, world!") == "^hello, ^world!"

    def test_unicode_text(self):
        result = apply_datamarking("héllo wörld 日本語")
        assert result == "^héllo ^wörld ^日本語"

    def test_custom_marker(self):
        assert apply_datamarking("hello world", marker="@") == "@hello @world"

    def test_multiline(self):
        text = "line one\nline two\nline three"
        expected = "^line ^one\n^line ^two\n^line ^three"
        assert apply_datamarking(text) == expected


class TestRemoveDatamarking:
    def test_single_word(self):
        assert remove_datamarking("^hello") == "hello"

    def test_multi_word(self):
        assert remove_datamarking("^hello ^world") == "hello world"

    def test_preserves_spaces(self):
        assert remove_datamarking("^a  ^b") == "a  b"

    def test_preserves_newlines(self):
        assert remove_datamarking("^line1\n^line2") == "line1\nline2"

    def test_empty_string(self):
        assert remove_datamarking("") == ""

    def test_custom_marker(self):
        assert remove_datamarking("@hello @world", marker="@") == "hello world"

    def test_unicode_text(self):
        assert remove_datamarking("^héllo ^wörld") == "héllo wörld"


class TestRoundTrip:
    def test_basic_round_trip(self):
        text = "hello world foo bar"
        assert remove_datamarking(apply_datamarking(text)) == text

    def test_multiline_round_trip(self):
        text = "line one\nline two\nline three"
        assert remove_datamarking(apply_datamarking(text)) == text

    def test_unicode_round_trip(self):
        text = "héllo wörld 日本語"
        assert remove_datamarking(apply_datamarking(text)) == text

    def test_custom_marker_round_trip(self):
        text = "foo bar baz"
        marker = "@"
        assert remove_datamarking(apply_datamarking(text, marker=marker), marker=marker) == text


# ── Marker unpredictability tests (T-005) ─────────────────────────

import random

from sentinel.security.pipeline import _generate_marker, _MARKER_POOL


class TestMarkerUnpredictability:
    """Regression guard: T-005 — spotlight marker cryptographic randomness.

    Verifies that the per-request marker is generated with secrets (CSPRNG),
    not stdlib random (predictable with known seed). Also checks diversity
    and absence from typical LLM output.
    """

    def test_markers_have_high_entropy(self):
        """Regression guard: 100 generated markers show expected diversity."""
        markers = [_generate_marker() for _ in range(100)]
        unique = len(set(markers))
        # Pool is 11 chars, length 4 → 14,641 possible markers.
        # 100 samples should yield ~99 unique (birthday bound allows a few
        # collisions). A broken generator returning constant output → unique=1.
        assert unique >= 90, (
            f"Only {unique}/100 unique markers — expected near-full diversity "
            f"from {len(_MARKER_POOL)}^4 = {len(_MARKER_POOL) ** 4} possibilities"
        )

    def test_marker_uses_secrets_not_random(self):
        """Regression guard: seeding stdlib random does not affect markers.

        secrets.choice() is backed by os.urandom and ignores random.seed().
        If the implementation used random.choice(), re-seeding would produce
        identical batches — a catastrophic predictability flaw.
        """
        random.seed(42)
        batch_a = [_generate_marker() for _ in range(20)]

        random.seed(42)
        batch_b = [_generate_marker() for _ in range(20)]

        # With secrets, these batches will differ (p(equal) ≈ 1/14641^20 ≈ 0)
        assert batch_a != batch_b, (
            "Marker generation appears deterministic — "
            "likely uses stdlib random instead of secrets"
        )

    def test_markers_absent_from_representative_output(self):
        """Regression guard: markers don't collide with typical Qwen output.

        The marker pool (~!@#%*+=|;:) avoids characters common in code and
        prose. A 4-char sequence of only pool characters should not appear
        in typical LLM output (code + explanation).
        """
        # Representative Qwen-style output: Python code + explanation
        output = (
            "Here's a Python script that reads a CSV file:\n"
            "\n"
            "```python\n"
            "import csv\n"
            "import json\n"
            "import os\n"
            "\n"
            "def read_csv(filename: str) -> list[dict]:\n"
            '    """Read a CSV file and return a list of dictionaries."""\n'
            "    with open(filename, 'r') as f:\n"
            "        reader = csv.DictReader(f)\n"
            "        return list(reader)\n"
            "\n"
            "if __name__ == '__main__':\n"
            "    data = read_csv('input.csv')\n"
            "    for row in data:\n"
            "        print(json.dumps(row, indent=2))\n"
            "```\n"
            "\n"
            "This function:\n"
            "1. Opens the file in read mode\n"
            "2. Uses csv.DictReader for header-based parsing\n"
            "3. Returns a list of dictionaries (one per row)\n"
            "\n"
            "You can modify the output format by changing the print statement.\n"
            "For example, you could write to a JSON file instead:\n"
            "\n"
            "```python\n"
            "with open('output.json', 'w') as f:\n"
            "    json.dump(data, f, indent=2)\n"
            "```\n"
        )

        # Generate 500 markers and check none appear in the output
        for _ in range(500):
            marker = _generate_marker()
            assert marker not in output, (
                f"Marker {marker!r} collided with representative Qwen output"
            )
