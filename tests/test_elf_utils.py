"""Tests for ELF binary analysis utilities."""

from src.utils.elf_utils import (
    get_elf_binary_info,
    _parse_elf_header,
    _validate_section_names,
    _count_load_segments,
    ELF_MAGIC,
    ELFCLASS32,
    ELFCLASS64,
)


class TestParseElfHeader:
    def test_invalid_magic(self):
        assert _parse_elf_header(b'\x00\x00\x00\x00' + b'\x00' * 60) is None

    def test_too_short(self):
        assert _parse_elf_header(b'\x7fEL') is None

    def test_invalid_class(self):
        header = b'\x7fELF\x03' + b'\x01' + b'\x00' * 58  # class=3 is invalid
        assert _parse_elf_header(header) is None

    def test_64bit_little_endian(self, elf64_path):
        with open(elf64_path, 'rb') as f:
            header = f.read(64)
        result = _parse_elf_header(header)
        assert result is not None
        ei_class, endian_char, *_ = result
        assert ei_class == ELFCLASS64
        assert endian_char == '<'

    def test_32bit_little_endian(self, elf32_path):
        with open(elf32_path, 'rb') as f:
            header = f.read(64)
        result = _parse_elf_header(header)
        assert result is not None
        ei_class, endian_char, *_ = result
        assert ei_class == ELFCLASS32
        assert endian_char == '<'


class TestGetElfBinaryInfo:
    def test_64bit_elf(self, elf64_path):
        info = get_elf_binary_info(elf64_path)
        assert info['bits'] == 64
        assert info['load_segments'] == 2
        assert info['has_section_name'] is True

    def test_32bit_elf(self, elf32_path):
        info = get_elf_binary_info(elf32_path)
        assert info['bits'] == 32
        assert info['load_segments'] == 2
        assert info['has_section_name'] is True

    def test_no_sections(self, elf_no_sections_path):
        info = get_elf_binary_info(elf_no_sections_path)
        assert info['bits'] == 64
        assert info['has_section_name'] is False

    def test_non_elf_file(self, non_elf_path):
        info = get_elf_binary_info(non_elf_path)
        assert info['bits'] is None
        assert info['load_segments'] is None
        assert info['has_section_name'] is None

    def test_nonexistent_file(self):
        info = get_elf_binary_info("/nonexistent/path")
        assert info['bits'] is None

    def test_empty_file(self, tmp_path):
        path = tmp_path / "empty"
        path.write_bytes(b"")
        info = get_elf_binary_info(str(path))
        assert info['bits'] is None
