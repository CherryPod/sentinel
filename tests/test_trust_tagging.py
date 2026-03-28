"""Tests for file trust tagging with content hash verification.

Validates that the provenance system correctly:
- Defaults to UNTRUSTED for files without provenance records
- Verifies content hashes to detect post-write tampering
- Treats legacy (empty-hash) records as UNTRUSTED
- Propagates UNTRUSTED from writer to reader
"""

import hashlib
import os
import tempfile

import pytest

from sentinel.core.models import DataSource, PolicyResult, TrustLevel, ValidationResult
from sentinel.security.provenance import (
    ProvenanceStore,
    create_tagged_data,
    get_file_writer,
    get_tagged_data,
    record_file_write,
    reset_store,
)
from sentinel.security.policy_engine import PolicyEngine
from sentinel.tools.executor import ToolExecutor

from unittest.mock import patch


@pytest.fixture(autouse=True)
async def _clean_store():
    await reset_store()


# ── Provenance store-level tests ──────────────────────────────


class TestContentHashProvenance:
    """Provenance store records and verifies content hashes."""

    async def test_record_stores_content_hash(self):
        """record_file_write stores SHA-256 of content alongside data_id."""
        tagged = await create_tagged_data("test", DataSource.TOOL, TrustLevel.TRUSTED)
        content = "hello world"
        expected_hash = hashlib.sha256(content.encode()).hexdigest()

        await record_file_write("/workspace/test.txt", tagged.id, content=content)
        result = await get_file_writer("/workspace/test.txt")

        assert result is not None
        data_id, content_hash = result
        assert data_id == tagged.id
        assert content_hash == expected_hash

    async def test_record_without_content_stores_empty_hash(self):
        """record_file_write without content stores hash of empty string."""
        tagged = await create_tagged_data("test", DataSource.TOOL, TrustLevel.TRUSTED)
        empty_hash = hashlib.sha256(b"").hexdigest()

        await record_file_write("/workspace/test.txt", tagged.id)
        result = await get_file_writer("/workspace/test.txt")

        assert result is not None
        _, content_hash = result
        assert content_hash == empty_hash

    async def test_overwrite_updates_hash(self):
        """Second record_file_write updates the content hash."""
        t1 = await create_tagged_data("first", DataSource.TOOL, TrustLevel.TRUSTED)
        t2 = await create_tagged_data("second", DataSource.TOOL, TrustLevel.TRUSTED)
        await record_file_write("/workspace/test.txt", t1.id, content="first content")
        await record_file_write("/workspace/test.txt", t2.id, content="second content")

        result = await get_file_writer("/workspace/test.txt")
        assert result is not None
        data_id, content_hash = result
        assert data_id == t2.id
        assert content_hash == hashlib.sha256(b"second content").hexdigest()

    async def test_binary_content_hashed_correctly(self):
        """record_file_write handles bytes content."""
        tagged = await create_tagged_data("bin", DataSource.TOOL, TrustLevel.TRUSTED)
        content = b"\x00\x01\x02\xff"
        expected_hash = hashlib.sha256(content).hexdigest()

        await record_file_write("/workspace/test.bin", tagged.id, content=content)
        result = await get_file_writer("/workspace/test.bin")

        assert result is not None
        assert result[1] == expected_hash


# ── Executor-level trust tagging tests ────────────────────────


class TestFileReadTrustTagging:
    """file_read trust assignment with hash verification (the security fix)."""

    @pytest.fixture
    def executor(self):
        engine = PolicyEngine("policies/sentinel-policy.yaml")
        return ToolExecutor(policy_engine=engine, trust_level=3)

    async def test_no_provenance_defaults_untrusted(self, executor):
        """Files without provenance records MUST be UNTRUSTED."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = f"{tmpdir}/unknown.txt"
            with open(path, "w") as f:
                f.write("user-placed file")

            with patch.object(executor._engine, "check_file_read") as mock_check:
                mock_check.return_value = ValidationResult(
                    status=PolicyResult.ALLOWED, path=path,
                )
                tagged, meta = await executor._file_read({"path": path})

            assert tagged.trust_level == TrustLevel.UNTRUSTED
            assert tagged.source == DataSource.FILE

    async def test_matching_hash_trusted(self, executor):
        """Files with provenance AND matching content hash inherit TRUSTED."""
        content = "legitimate content written by Sentinel"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = f"{tmpdir}/written.txt"

            # Simulate file_write: write file and record provenance with hash
            with open(path, "w") as f:
                f.write(content)
            write_tag = await create_tagged_data(
                f"File written: {path}", DataSource.TOOL, TrustLevel.TRUSTED,
            )
            await record_file_write(path, write_tag.id, content=content)

            with patch.object(executor._engine, "check_file_read") as mock_check:
                mock_check.return_value = ValidationResult(
                    status=PolicyResult.ALLOWED, path=path,
                )
                tagged, meta = await executor._file_read({"path": path})

            assert tagged.trust_level == TrustLevel.TRUSTED

    async def test_mismatched_hash_untrusted(self, executor):
        """Files with provenance but DIFFERENT content hash are UNTRUSTED.

        This is the provenance-overwrite attack: shell_exec overwrites a
        Sentinel-written file, then file_read inherits stale TRUSTED status.
        With hash verification, the overwrite is detected.
        """
        original = "legitimate content"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = f"{tmpdir}/overwritten.txt"

            # Sentinel writes the file and records provenance
            with open(path, "w") as f:
                f.write(original)
            write_tag = await create_tagged_data(
                f"File written: {path}", DataSource.TOOL, TrustLevel.TRUSTED,
            )
            await record_file_write(path, write_tag.id, content=original)

            # Attacker overwrites via shell_exec (no provenance update)
            with open(path, "w") as f:
                f.write("malicious overwrite with injected instructions")

            with patch.object(executor._engine, "check_file_read") as mock_check:
                mock_check.return_value = ValidationResult(
                    status=PolicyResult.ALLOWED, path=path,
                )
                tagged, meta = await executor._file_read({"path": path})

            # Hash mismatch → UNTRUSTED (attack detected)
            assert tagged.trust_level == TrustLevel.UNTRUSTED

    async def test_untrusted_writer_stays_untrusted(self, executor):
        """Files written from UNTRUSTED source stay UNTRUSTED regardless of hash."""
        content = "content from untrusted source"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = f"{tmpdir}/untrusted.txt"
            with open(path, "w") as f:
                f.write(content)

            write_tag = await create_tagged_data(
                f"File written: {path}", DataSource.TOOL, TrustLevel.UNTRUSTED,
            )
            await record_file_write(path, write_tag.id, content=content)

            with patch.object(executor._engine, "check_file_read") as mock_check:
                mock_check.return_value = ValidationResult(
                    status=PolicyResult.ALLOWED, path=path,
                )
                tagged, meta = await executor._file_read({"path": path})

            assert tagged.trust_level == TrustLevel.UNTRUSTED

    async def test_orphaned_provenance_fails_closed(self, executor):
        """If provenance record exists but tagged data is gone, default UNTRUSTED."""
        content = "some content"
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = f"{tmpdir}/orphaned.txt"
            with open(path, "w") as f:
                f.write(content)

            # Record provenance with a data_id that doesn't exist in the store
            # (simulates data eviction or corruption). Key is (path, user_id) — use
            # user_id=0 (orphan/default) to match the no-user-context code path.
            from sentinel.security.provenance import _default_store
            _default_store._file_provenance[(path, 0)] = ("nonexistent-data-id", content_hash)

            with patch.object(executor._engine, "check_file_read") as mock_check:
                mock_check.return_value = ValidationResult(
                    status=PolicyResult.ALLOWED, path=path,
                )
                tagged, meta = await executor._file_read({"path": path})

            # Orphaned record (get_tagged_data returns None) → UNTRUSTED
            assert tagged.trust_level == TrustLevel.UNTRUSTED

    async def test_legacy_empty_hash_untrusted(self, executor):
        """Legacy provenance records (empty hash from pre-migration) are UNTRUSTED."""
        content = "file with legacy provenance"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = f"{tmpdir}/legacy.txt"
            with open(path, "w") as f:
                f.write(content)

            # Simulate a legacy record: data_id exists but hash is empty
            write_tag = await create_tagged_data(
                f"File written: {path}", DataSource.TOOL, TrustLevel.TRUSTED,
            )
            # Directly inject legacy-style record with empty hash. Key is (path, user_id)
            # — use user_id=0 (orphan/default) to match the no-user-context code path.
            from sentinel.security.provenance import _default_store
            _default_store._file_provenance[(path, 0)] = (write_tag.id, "")

            with patch.object(executor._engine, "check_file_read") as mock_check:
                mock_check.return_value = ValidationResult(
                    status=PolicyResult.ALLOWED, path=path,
                )
                tagged, meta = await executor._file_read({"path": path})

            # Empty hash → treated as UNTRUSTED (can't verify integrity)
            assert tagged.trust_level == TrustLevel.UNTRUSTED

    async def test_full_write_read_roundtrip(self, executor):
        """End-to-end: file_write → file_read preserves TRUSTED via hash."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = f"{tmpdir}/roundtrip.txt"

            with patch.object(executor._engine, "check_file_write") as mock_write:
                mock_write.return_value = ValidationResult(
                    status=PolicyResult.ALLOWED, path=path,
                )
                with patch("sentinel.tools.executor.semgrep_scanner") as mock_sg:
                    mock_sg.is_loaded.return_value = False
                    write_result, _ = await executor.execute("file_write", {
                        "path": path,
                        "content": "test content for roundtrip",
                    })

            with patch.object(executor._engine, "check_file_read") as mock_read:
                mock_read.return_value = ValidationResult(
                    status=PolicyResult.ALLOWED, path=path,
                )
                read_result, _ = await executor._file_read({"path": path})

            # Content matches provenance hash → TRUSTED
            assert read_result.trust_level == TrustLevel.TRUSTED
