"""Tests for sentinel.memory.splitter — text chunking logic."""

from sentinel.memory.splitter import split_text, _split_by_words, _merge_segments


class TestSplitText:
    """split_text() — paragraph, sentence, and word boundary splitting."""

    def test_empty_string_returns_empty(self):
        assert split_text("") == []

    def test_whitespace_only_returns_empty(self):
        assert split_text("   \n\n  \t  ") == []

    def test_short_text_single_chunk(self):
        text = "Hello world. This is a short text."
        result = split_text(text)
        assert len(result) == 1
        assert result[0] == text

    def test_paragraph_split(self):
        """Double-newline should split into separate segments."""
        para1 = "First paragraph with some words."
        para2 = "Second paragraph with more words."
        text = f"{para1}\n\n{para2}"
        result = split_text(text, target_words=100)
        # Both paragraphs are short enough to merge into one chunk
        assert len(result) == 1
        assert "First paragraph" in result[0]
        assert "Second paragraph" in result[0]

    def test_paragraph_split_exceeds_target(self):
        """When paragraphs exceed target, they should be in separate chunks."""
        # Create two paragraphs of ~50 words each, target=40
        words = " ".join(f"word{i}" for i in range(50))
        text = f"{words}\n\n{words}"
        result = split_text(text, target_words=40, overlap_words=5)
        assert len(result) >= 2

    def test_sentence_boundary_split(self):
        """Long paragraphs should split on sentence boundaries."""
        # One paragraph with multiple sentences, each ~15 words
        sentences = [
            "The quick brown fox jumps over the lazy dog in the field. ",
            "A second sentence with enough words to take up some space. ",
            "Yet another sentence that adds more words to this paragraph. ",
            "And finally a fourth sentence to push past the word target. ",
        ]
        text = " ".join(sentences)  # single paragraph
        result = split_text(text, target_words=25, overlap_words=3)
        assert len(result) >= 2

    def test_word_boundary_split_for_huge_sentence(self):
        """A single very long sentence should split on word boundaries."""
        text = " ".join(f"word{i}" for i in range(200))
        result = split_text(text, target_words=50, overlap_words=5)
        assert len(result) >= 3
        for chunk in result:
            # Each chunk should be close to target (with some tolerance for overlap)
            word_count = len(chunk.split())
            assert word_count <= 60  # target + overlap tolerance

    def test_overlap_present(self):
        """Chunks should overlap — last N words of chunk K appear in chunk K+1."""
        words = " ".join(f"w{i}" for i in range(100))
        result = split_text(words, target_words=30, overlap_words=5)
        assert len(result) >= 3
        # Check overlap between first two chunks
        first_words = result[0].split()
        second_words = result[1].split()
        overlap = first_words[-5:]
        # The overlap words should appear at the start of the next chunk
        assert second_words[:5] == overlap

    def test_overlap_zero(self):
        """overlap_words=0 should produce no overlap."""
        words = " ".join(f"w{i}" for i in range(100))
        result = split_text(words, target_words=30, overlap_words=0)
        assert len(result) >= 3
        # Check no overlap — last word of chunk 0 should not be first word of chunk 1
        first_last = result[0].split()[-1]
        second_first = result[1].split()[0]
        assert first_last != second_first

    def test_single_word(self):
        assert split_text("hello") == ["hello"]

    def test_preserves_content(self):
        """All original words should appear in at least one chunk."""
        original_words = [f"word{i}" for i in range(50)]
        text = " ".join(original_words)
        result = split_text(text, target_words=20, overlap_words=3)
        all_chunk_words = set()
        for chunk in result:
            all_chunk_words.update(chunk.split())
        for w in original_words:
            assert w in all_chunk_words

    def test_mixed_paragraph_sizes(self):
        """Mix of short and long paragraphs."""
        short = "Short paragraph."
        long_para = " ".join(f"word{i}" for i in range(100))
        text = f"{short}\n\n{long_para}\n\n{short}"
        result = split_text(text, target_words=40, overlap_words=5)
        assert len(result) >= 2

    def test_triple_newlines_treated_as_paragraph_break(self):
        """Three or more newlines should still split paragraphs."""
        text = "First part.\n\n\nSecond part."
        result = split_text(text, target_words=100)
        assert len(result) == 1
        assert "First part" in result[0]
        assert "Second part" in result[0]

    def test_default_target_words(self):
        """Default target_words=380 should handle typical document text."""
        # 760 words should produce ~2 chunks at default settings
        text = " ".join(f"word{i}" for i in range(760))
        result = split_text(text)
        assert len(result) >= 2


class TestSplitByWords:
    """_split_by_words() — exact word boundary splitting."""

    def test_exact_multiple(self):
        text = " ".join(f"w{i}" for i in range(10))
        result = _split_by_words(text, 5)
        assert len(result) == 2
        assert len(result[0].split()) == 5
        assert len(result[1].split()) == 5

    def test_remainder(self):
        text = " ".join(f"w{i}" for i in range(7))
        result = _split_by_words(text, 5)
        assert len(result) == 2
        assert len(result[0].split()) == 5
        assert len(result[1].split()) == 2


class TestMergeSegments:
    """_merge_segments() — segment merging with overlap."""

    def test_empty_segments(self):
        assert _merge_segments([], 100, 10) == []

    def test_single_segment(self):
        result = _merge_segments(["hello world"], 100, 10)
        assert result == ["hello world"]

    def test_segments_below_target_merge(self):
        segments = ["hello", "world"]
        result = _merge_segments(segments, 100, 10)
        assert len(result) == 1
        assert result[0] == "hello world"
