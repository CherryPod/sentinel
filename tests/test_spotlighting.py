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
