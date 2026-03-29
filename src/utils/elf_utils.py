"""
ELF binary analysis utilities using pyelftools and struct parsing.
"""

import struct
import logging
from elftools.elf.elffile import ELFFile
from elftools.elf.descriptions import describe_e_machine

# ELF constants
ELF_MAGIC = b'\x7fELF'
ELFCLASS32 = 1
ELFCLASS64 = 2
PT_LOAD = 1

# Section header entry sizes
SH_ENTRY_SIZE_32 = 40
SH_ENTRY_SIZE_64 = 64

# ELF file type mapping
_ELF_TYPE_MAP = {
    'ET_EXEC': 'EXEC',
    'ET_DYN': 'DYN',
    'ET_REL': 'REL',
    'ET_CORE': 'CORE',
}


def get_elf_info_with_pyelftools(binary_path):
    """
    Get CPU, endianness, file type, and stripped status using pyelftools.

    :param binary_path: Path to the binary file.
    :return: Dictionary with 'cpu', 'endianness', 'file_type', 'is_stripped' keys, or all None if error occurs.
    """
    info = {
        'cpu': None,
        'endianness': None,
        'file_type': None,
        'is_stripped': None
    }

    try:
        with open(binary_path, 'rb') as f:
            elffile = ELFFile(f)

            info['cpu'] = describe_e_machine(elffile.header['e_machine'])

            info['endianness'] = (
                "2's complement, little endian" if elffile.little_endian
                else "2's complement, big endian"
            )

            e_type = elffile.header['e_type']
            info['file_type'] = _ELF_TYPE_MAP.get(e_type, e_type)

            info['is_stripped'] = elffile.get_section_by_name('.symtab') is None

        return info

    except Exception as e:
        logging.debug(f"Error reading ELF info with pyelftools from {binary_path}: {e}")
        return info


def _parse_elf_header(header):
    """
    Parse ELF header bytes and return structured field values.

    :param header: Raw bytes of ELF header (at least 64 bytes).
    :return: Tuple of (ei_class, endian_char, e_phoff, e_shoff, e_phentsize, e_phnum, e_shnum, e_shstrndx, sh_entry_size)
             or None if header is invalid.
    """
    if len(header) < 5 or header[:4] != ELF_MAGIC:
        return None

    ei_class = header[4]
    ei_data = header[5]

    if ei_class not in (ELFCLASS32, ELFCLASS64):
        return None

    endian_char = '<' if ei_data == 1 else '>'

    if ei_class == ELFCLASS32:
        e_phoff = struct.unpack(f'{endian_char}I', header[28:32])[0]
        e_shoff = struct.unpack(f'{endian_char}I', header[32:36])[0]
        e_phentsize = struct.unpack(f'{endian_char}H', header[42:44])[0]
        e_phnum = struct.unpack(f'{endian_char}H', header[44:46])[0]
        e_shnum = struct.unpack(f'{endian_char}H', header[48:50])[0]
        e_shstrndx = struct.unpack(f'{endian_char}H', header[50:52])[0]
        sh_entry_size = SH_ENTRY_SIZE_32
    else:
        e_phoff = struct.unpack(f'{endian_char}Q', header[32:40])[0]
        e_shoff = struct.unpack(f'{endian_char}Q', header[40:48])[0]
        e_phentsize = struct.unpack(f'{endian_char}H', header[54:56])[0]
        e_phnum = struct.unpack(f'{endian_char}H', header[56:58])[0]
        e_shnum = struct.unpack(f'{endian_char}H', header[60:62])[0]
        e_shstrndx = struct.unpack(f'{endian_char}H', header[62:64])[0]
        sh_entry_size = SH_ENTRY_SIZE_64

    return (ei_class, endian_char, e_phoff, e_shoff, e_phentsize,
            e_phnum, e_shnum, e_shstrndx, sh_entry_size)


def _validate_section_names(f, ei_class, endian_char, e_shoff, e_shnum, e_shstrndx, sh_entry_size):
    """
    Validate whether the ELF file has a valid section name string table.

    :return: True if valid section names exist, False otherwise.
    """
    if e_shnum == 0 or e_shstrndx == 0 or e_shstrndx >= e_shnum:
        return False

    try:
        shstrtab_header_offset = e_shoff + (e_shstrndx * sh_entry_size)
        f.seek(shstrtab_header_offset)
        shstrtab_header = f.read(sh_entry_size)

        if len(shstrtab_header) != sh_entry_size:
            return False

        # Parse sh_offset and sh_size from section header
        if ei_class == ELFCLASS32:
            sh_offset = struct.unpack(f'{endian_char}I', shstrtab_header[16:20])[0]
            sh_size_val = struct.unpack(f'{endian_char}I', shstrtab_header[20:24])[0]
        else:
            sh_offset = struct.unpack(f'{endian_char}Q', shstrtab_header[24:32])[0]
            sh_size_val = struct.unpack(f'{endian_char}Q', shstrtab_header[32:40])[0]

        if sh_offset == 0 or sh_size_val == 0:
            return False

        file_size = f.seek(0, 2)
        return sh_offset < file_size and sh_offset + sh_size_val <= file_size

    except Exception:
        return False


def _count_load_segments(f, endian_char, e_phoff, e_phentsize, e_phnum):
    """
    Count the number of PT_LOAD segments in the ELF file.

    :return: Number of PT_LOAD segments.
    """
    f.seek(e_phoff)
    load_count = 0

    for _ in range(e_phnum):
        ph = f.read(e_phentsize)
        if len(ph) < 4:
            break
        p_type = struct.unpack(f'{endian_char}I', ph[:4])[0]
        if p_type == PT_LOAD:
            load_count += 1

    return load_count


def get_elf_binary_info(binary_path):
    """
    Read ELF file once to get bits, load segments count, and section headers info.

    :param binary_path: Path to the binary file
    :return: Dictionary with 'bits', 'load_segments', 'has_section_name' keys, or all None if error
    """
    info = {
        'bits': None,
        'load_segments': None,
        'has_section_name': None
    }

    try:
        with open(binary_path, 'rb') as f:
            header = f.read(64)

            parsed = _parse_elf_header(header)
            if parsed is None:
                return info

            (ei_class, endian_char, e_phoff, e_shoff, e_phentsize,
             e_phnum, e_shnum, e_shstrndx, sh_entry_size) = parsed

            info['bits'] = 32 if ei_class == ELFCLASS32 else 64

            info['has_section_name'] = _validate_section_names(
                f, ei_class, endian_char, e_shoff, e_shnum, e_shstrndx, sh_entry_size
            )

            info['load_segments'] = _count_load_segments(
                f, endian_char, e_phoff, e_phentsize, e_phnum
            )

            return info

    except Exception as e:
        logging.debug(f"Error reading ELF binary info from {binary_path}: {e}")
        return info
