"""Text splitter for memory chunks.

Splits text on paragraph → sentence → word boundaries with configurable
overlap. Target ~380 words per chunk (≈512 tokens at ~1.35 words/token).
"""

import re

# Sentence-ending punctuation followed by whitespace
_SENTENCE_BOUNDARY = re.compile(r"(?<=[.!?])\s+")


def split_text(
    text: str,
    target_words: int = 380,
    overlap_words: int = 35,
) -> list[str]:
    """Split text into chunks of approximately target_words with overlap.

    Strategy:
    1. Split on double-newlines (paragraphs)
    2. If a paragraph exceeds target, split on sentence boundaries
    3. If a sentence still exceeds target, split on word boundaries
    4. Overlap: last overlap_words of chunk N are prepended to chunk N+1

    Returns list of chunk strings. Empty/whitespace-only text returns [].
    """
    text = text.strip()
    if not text:
        return []

    # Split into paragraphs on double-newlines
    paragraphs = re.split(r"\n\s*\n", text)
    paragraphs = [p.strip() for p in paragraphs if p.strip()]

    if not paragraphs:
        return []

    # Break paragraphs that exceed target into sentences, then words
    segments = []
    for para in paragraphs:
        word_count = len(para.split())
        if word_count <= target_words:
            segments.append(para)
        else:
            # Split paragraph into sentences
            sentences = _SENTENCE_BOUNDARY.split(para)
            sentences = [s.strip() for s in sentences if s.strip()]
            for sentence in sentences:
                s_word_count = len(sentence.split())
                if s_word_count <= target_words:
                    segments.append(sentence)
                else:
                    # Split long sentence into word-boundary chunks
                    segments.extend(_split_by_words(sentence, target_words))

    # Merge segments into chunks of ~target_words with overlap
    return _merge_segments(segments, target_words, overlap_words)


def _split_by_words(text: str, target_words: int) -> list[str]:
    """Split a long text into chunks of exactly target_words words."""
    words = text.split()
    chunks = []
    for i in range(0, len(words), target_words):
        chunk = " ".join(words[i : i + target_words])
        if chunk:
            chunks.append(chunk)
    return chunks


def _merge_segments(
    segments: list[str],
    target_words: int,
    overlap_words: int,
) -> list[str]:
    """Merge small segments into chunks, adding overlap between chunks."""
    if not segments:
        return []

    chunks: list[str] = []
    current_words: list[str] = []

    for segment in segments:
        seg_words = segment.split()

        # If adding this segment exceeds target, flush current chunk
        if current_words and len(current_words) + len(seg_words) > target_words:
            chunks.append(" ".join(current_words))
            # Overlap: carry last N words into next chunk
            if overlap_words > 0 and len(current_words) > overlap_words:
                current_words = current_words[-overlap_words:]
            else:
                current_words = []

        current_words.extend(seg_words)

    # Flush remaining words
    if current_words:
        chunks.append(" ".join(current_words))

    return chunks
