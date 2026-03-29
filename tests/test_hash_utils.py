"""Tests for hash utilities."""

import hashlib
from src.utils.hash_utils import calculate_file_hashes


class TestCalculateFileHashes:
    def test_known_content(self, tmp_path):
        path = tmp_path / "test_file"
        content = b"hello world"
        path.write_bytes(content)

        sha256, md5 = calculate_file_hashes(str(path))

        assert sha256 == hashlib.sha256(content).hexdigest()
        assert md5 == hashlib.md5(content).hexdigest()

    def test_empty_file(self, tmp_path):
        path = tmp_path / "empty"
        path.write_bytes(b"")

        sha256, md5 = calculate_file_hashes(str(path))

        assert sha256 == hashlib.sha256(b"").hexdigest()
        assert md5 == hashlib.md5(b"").hexdigest()

    def test_nonexistent_file(self):
        sha256, md5 = calculate_file_hashes("/nonexistent/path")
        assert sha256 is None
        assert md5 is None

    def test_large_file(self, tmp_path):
        """Verify chunked reading works for files larger than buffer size."""
        path = tmp_path / "large_file"
        content = b"x" * 100_000
        path.write_bytes(content)

        sha256, md5 = calculate_file_hashes(str(path))

        assert sha256 == hashlib.sha256(content).hexdigest()
        assert md5 == hashlib.md5(content).hexdigest()
