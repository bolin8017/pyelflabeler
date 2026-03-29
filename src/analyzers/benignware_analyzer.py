"""
Benignware analyzer - processes binary files only.
"""

import os
import logging
from tqdm import tqdm

from src.analyzers.base_analyzer import BaseAnalyzer
from src.config import Config
from src.utils.elf_utils import enrich_result_with_binary_info
from src.utils.hash_utils import calculate_file_hashes


class BenignwareAnalyzer(BaseAnalyzer):
    """Analyzer for benignware datasets with binary files only."""

    def __init__(self, config: Config):
        """
        Initialize the BenignwareAnalyzer object.

        :param config: Configuration object containing input directory and output path.
        """
        super().__init__(config)

        if not os.path.isdir(self.binary_base_path):
            raise ValueError(f"Binary directory does not exist: {self.binary_base_path}")

    def collect_files(self):
        """
        Get all binary files from the binary directory.
        Files are organized as: base_dir/hash[:2]/hash
        """
        print(f"Searching for all binary files in directory: {self.binary_base_path}...")

        try:
            subdirs = list(os.scandir(self.binary_base_path))
        except OSError as e:
            logging.warning(f"Error reading directory {self.binary_base_path}: {e}")
            return

        for entry in tqdm(subdirs, desc="Scanning subdirectories", unit="dir"):
            if not entry.is_dir() or len(entry.name) != 2:
                continue

            try:
                for file_entry in os.scandir(entry.path):
                    if file_entry.is_file():
                        self.file_list.append(file_entry.path)
            except OSError as e:
                logging.warning(f"Error reading directory {entry.path}: {e}")
                continue

        print(f"Found {len(self.file_list)} binary files")

    @staticmethod
    def process_single_file(binary_path):
        """
        Process a single benignware binary file.

        :param binary_path: Path to the binary file.
        :return: Dictionary containing extracted information, or None if processing failed.
        """
        sha256, md5 = calculate_file_hashes(binary_path)

        try:
            file_size = os.path.getsize(binary_path)
        except (OSError, IOError):
            file_size = 0

        result = {
            'file_name': sha256,
            'md5': md5,
            'label': 'Benignware',
            'file_type': None,
            'CPU': None,
            'bits': None,
            'endianness': None,
            'load_segments': None,
            'is_stripped': None,
            'has_section_name': None,
            'family': None,
            'first_seen': None,
            'size': file_size,
            'diec_is_packed': False,
            'diec_packer_info': None,
            'diec_packing_method': None
        }

        if not sha256:
            return result

        enrich_result_with_binary_info(result, binary_path)
        return result
