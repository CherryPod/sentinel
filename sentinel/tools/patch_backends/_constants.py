"""Shared constants for patch backend implementations."""

# Maximum byte span for anchor resolution — prevents excessive memory usage
# when extracting code blocks around anchors.
SPAN_MAX_BYTES = 10240

# Minimum byte span for anchor resolution — skip trivially small spans
# that can't contain meaningful code.
SPAN_MIN_BYTES_DEFAULT = 10
SPAN_MIN_BYTES_PYTHON = 5

# Replace anchor size thresholds (characters)
REPLACE_ANCHOR_HARD_LIMIT = 2000  # Reject anchors larger than this
REPLACE_ANCHOR_WARN_LIMIT = 500  # Warn (but allow) anchors larger than this

# Fuzzy match deduplication region size (characters) — overlapping matches
# within the same region are deduplicated, keeping the best score.
FUZZY_DEDUP_REGION_SIZE = 50
