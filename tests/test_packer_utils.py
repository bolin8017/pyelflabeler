"""Tests for packer detection utilities."""

import json
import pytest
from src.utils.packer_utils import clean_ansi_codes, parse_diec_output, convert_to_one_line


class TestCleanAnsiCodes:
    def test_no_ansi(self):
        assert clean_ansi_codes("hello world") == "hello world"

    def test_color_codes(self):
        assert clean_ansi_codes("\x1b[31mred\x1b[0m") == "red"

    def test_bold_underline(self):
        assert clean_ansi_codes("\x1b[1m\x1b[4mbold underline\x1b[0m") == "bold underline"

    def test_complex_sequence(self):
        text = "\x1b[38;5;196mcolored\x1b[0m normal"
        assert clean_ansi_codes(text) == "colored normal"

    def test_empty_string(self):
        assert clean_ansi_codes("") == ""


class TestParseDiecOutput:
    def test_no_packer(self):
        result = parse_diec_output("ELF64\nLinker: GNU ld")
        assert result['diec_is_packed'] is False
        assert result['diec_packer_info'] is None
        assert result['diec_packing_method'] is None

    def test_upx_with_method(self):
        result = parse_diec_output("Packer: UPX(3.95)[NRV,brute]")
        assert result['diec_is_packed'] is True
        assert result['diec_packer_info'] == "UPX(3.95)"
        assert result['diec_packing_method'] == "NRV,brute"

    def test_upx_without_method(self):
        result = parse_diec_output("Packer: UPX(4.02)")
        assert result['diec_is_packed'] is True
        assert result['diec_packer_info'] == "UPX(4.02)"
        assert result['diec_packing_method'] is None

    def test_multiline_with_packer(self):
        output = "ELF64\nLinker: GNU ld\nPacker: UPX(3.95)[NRV,brute]\nOther info"
        result = parse_diec_output(output)
        assert result['diec_is_packed'] is True
        assert result['diec_packer_info'] == "UPX(3.95)"

    def test_with_ansi_codes(self):
        output = "\x1b[31mPacker: UPX(3.95)[NRV]\x1b[0m"
        result = parse_diec_output(output)
        assert result['diec_is_packed'] is True
        assert result['diec_packer_info'] == "UPX(3.95)"

    def test_empty_output(self):
        result = parse_diec_output("")
        assert result['diec_is_packed'] is False


class TestConvertToOneLine:
    def test_valid_json(self, tmp_path):
        json_file = tmp_path / "test.json"
        data = {"sha256": "abc123", "positives": 5}
        json_file.write_text(json.dumps(data, indent=2))

        one_line, parsed = convert_to_one_line(str(json_file))
        assert one_line is not None
        assert parsed == data
        assert "\n" not in one_line

    def test_invalid_json(self, tmp_path):
        json_file = tmp_path / "bad.json"
        json_file.write_text("not json {{{")

        one_line, parsed = convert_to_one_line(str(json_file))
        assert one_line is None
        assert parsed is None

    def test_nonexistent_file(self):
        one_line, parsed = convert_to_one_line("/nonexistent/file.json")
        assert one_line is None
        assert parsed is None
