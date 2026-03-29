"""Tests for configuration management."""

import pytest
from src.config import Config


class TestConfig:
    def test_malware_mode_defaults(self, tmp_path):
        input_dir = str(tmp_path / "json")
        input_dir_path = tmp_path / "json"
        input_dir_path.mkdir()
        binary_dir = str(tmp_path / "bin")

        config = Config(mode='malware', input_dir=input_dir, binary_dir=binary_dir)

        assert config.mode == 'malware'
        assert config.input_dir == input_dir
        assert config.binary_base_path == binary_dir
        assert config.output_path.endswith("malware_info.csv")

    def test_benignware_mode_defaults(self, tmp_path):
        binary_dir = str(tmp_path / "bin")

        config = Config(mode='benignware', binary_dir=binary_dir)

        assert config.mode == 'benignware'
        assert config.output_path == "benignware_info.csv"

    def test_custom_output_path(self, tmp_path):
        config = Config(mode='benignware', binary_dir=str(tmp_path), output_path="custom.csv")
        assert config.output_path == "custom.csv"

    def test_missing_binary_dir_raises(self):
        with pytest.raises(ValueError, match="binary_dir is required"):
            Config(mode='malware', binary_dir=None)

    def test_empty_binary_dir_raises(self):
        with pytest.raises(ValueError, match="binary_dir is required"):
            Config(mode='malware', binary_dir="")


class TestFactory:
    def test_create_malware_analyzer(self, tmp_path):
        from src.factory import create_analyzer
        input_dir = tmp_path / "json"
        input_dir.mkdir()
        binary_dir = tmp_path / "bin"
        binary_dir.mkdir()
        config = Config(mode='malware', input_dir=str(input_dir), binary_dir=str(binary_dir))

        analyzer = create_analyzer(config)

        from src.analyzers.malware_analyzer import MalwareAnalyzer
        assert isinstance(analyzer, MalwareAnalyzer)

    def test_create_benignware_analyzer(self, tmp_path):
        from src.factory import create_analyzer
        binary_dir = tmp_path / "bin"
        binary_dir.mkdir()
        config = Config(mode='benignware', binary_dir=str(binary_dir))

        analyzer = create_analyzer(config)

        from src.analyzers.benignware_analyzer import BenignwareAnalyzer
        assert isinstance(analyzer, BenignwareAnalyzer)

    def test_unknown_mode_raises(self, tmp_path):
        from src.factory import create_analyzer
        config = Config(mode='benignware', binary_dir=str(tmp_path))
        config.mode = 'unknown'

        with pytest.raises(ValueError, match="Unknown mode"):
            create_analyzer(config)
