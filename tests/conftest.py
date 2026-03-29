"""
Shared test fixtures for pyelflabeler tests.
"""

import struct
import pytest

from src.utils.elf_utils import ELFCLASS32, ELFCLASS64, SH_ENTRY_SIZE_32, SH_ENTRY_SIZE_64


def _build_minimal_elf(bits=64, little_endian=True, num_loads=2, with_sections=True):
    """Build a minimal valid ELF binary for testing."""
    endian = '<' if little_endian else '>'
    ei_class = ELFCLASS32 if bits == 32 else ELFCLASS64

    # ELF magic + EI_CLASS + EI_DATA + EI_VERSION + padding
    e_ident = b'\x7fELF'
    e_ident += struct.pack('B', ei_class)
    e_ident += struct.pack('B', 1 if little_endian else 2)
    e_ident += struct.pack('B', 1)  # EV_CURRENT
    e_ident += b'\x00' * 9  # padding to 16 bytes

    if bits == 32:
        ehdr_size = 52
        phdr_size = 32
        shdr_size = SH_ENTRY_SIZE_32

        # Build program headers (PT_LOAD entries)
        phdrs = b''
        for i in range(num_loads):
            phdr = struct.pack(f'{endian}IIIIIIII',
                1,           # p_type = PT_LOAD
                0, 0, 0,    # p_offset, p_vaddr, p_paddr
                0, 0,        # p_filesz, p_memsz
                0, 0)        # p_flags, p_align
            phdrs += phdr

        ph_offset = ehdr_size
        sh_offset = ehdr_size + len(phdrs)

        if with_sections:
            # Section 0: null, Section 1: .shstrtab
            shstrtab_content = b'\x00.shstrtab\x00'
            shstrtab_offset = sh_offset + shdr_size * 2
            shstrtab_size = len(shstrtab_content)

            # Section header 0 (null)
            shdr0 = struct.pack(f'{endian}IIIIIIIIII', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
            # Section header 1 (.shstrtab)
            shdr1 = struct.pack(f'{endian}IIIIIIIIII',
                1,               # sh_name (offset into shstrtab)
                3,               # sh_type = SHT_STRTAB
                0,               # sh_flags
                0,               # sh_addr
                shstrtab_offset, # sh_offset
                shstrtab_size,   # sh_size
                0, 0, 0, 0)     # sh_link, sh_info, sh_addralign, sh_entsize
            shdrs = shdr0 + shdr1
            e_shnum = 2
            e_shstrndx = 1
        else:
            shdrs = b''
            shstrtab_content = b''
            e_shnum = 0
            e_shstrndx = 0

        # ELF header fields after e_ident
        ehdr_rest = struct.pack(f'{endian}HHIIIIIHHHHHH',
            2,            # e_type = ET_EXEC
            3,            # e_machine = EM_386
            1,            # e_version
            0,            # e_entry
            ph_offset,    # e_phoff
            sh_offset,    # e_shoff
            0,            # e_flags
            ehdr_size,    # e_ehsize
            phdr_size,    # e_phentsize
            num_loads,    # e_phnum
            shdr_size,    # e_shentsize
            e_shnum,      # e_shnum
            e_shstrndx)   # e_shstrndx

        return e_ident + ehdr_rest + phdrs + shdrs + shstrtab_content

    else:  # 64-bit
        ehdr_size = 64
        phdr_size = 56
        shdr_size = SH_ENTRY_SIZE_64

        phdrs = b''
        for i in range(num_loads):
            phdr = struct.pack(f'{endian}IIQQQQQQ',
                1,           # p_type = PT_LOAD
                0,           # p_flags
                0, 0, 0,    # p_offset, p_vaddr, p_paddr
                0, 0,        # p_filesz, p_memsz
                0)           # p_align
            phdrs += phdr

        ph_offset = ehdr_size
        sh_offset = ehdr_size + len(phdrs)

        if with_sections:
            shstrtab_content = b'\x00.shstrtab\x00'
            shstrtab_offset = sh_offset + shdr_size * 2
            shstrtab_size = len(shstrtab_content)

            # Section header 0 (null)
            shdr0 = struct.pack(f'{endian}IIQQQQIIQQ', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
            # Section header 1 (.shstrtab)
            shdr1 = struct.pack(f'{endian}IIQQQQIIQQ',
                1,               # sh_name
                3,               # sh_type = SHT_STRTAB
                0,               # sh_flags
                0,               # sh_addr
                shstrtab_offset, # sh_offset
                shstrtab_size,   # sh_size
                0, 0,            # sh_link, sh_info
                0, 0)            # sh_addralign, sh_entsize
            shdrs = shdr0 + shdr1
            e_shnum = 2
            e_shstrndx = 1
        else:
            shdrs = b''
            shstrtab_content = b''
            e_shnum = 0
            e_shstrndx = 0

        ehdr_rest = struct.pack(f'{endian}HHIQQQIHHHHHH',
            2,            # e_type = ET_EXEC
            62,           # e_machine = EM_X86_64
            1,            # e_version
            0,            # e_entry
            ph_offset,    # e_phoff
            sh_offset,    # e_shoff
            0,            # e_flags
            ehdr_size,    # e_ehsize
            phdr_size,    # e_phentsize
            num_loads,    # e_phnum
            shdr_size,    # e_shentsize
            e_shnum,      # e_shnum
            e_shstrndx)   # e_shstrndx

        return e_ident + ehdr_rest + phdrs + shdrs + shstrtab_content


@pytest.fixture
def elf64_path(tmp_path):
    """Create a minimal 64-bit ELF binary."""
    path = tmp_path / "test_elf64"
    path.write_bytes(_build_minimal_elf(bits=64))
    return str(path)


@pytest.fixture
def elf32_path(tmp_path):
    """Create a minimal 32-bit ELF binary."""
    path = tmp_path / "test_elf32"
    path.write_bytes(_build_minimal_elf(bits=32))
    return str(path)


@pytest.fixture
def elf_no_sections_path(tmp_path):
    """Create an ELF binary without section headers."""
    path = tmp_path / "test_elf_nosec"
    path.write_bytes(_build_minimal_elf(bits=64, with_sections=False))
    return str(path)


@pytest.fixture
def non_elf_path(tmp_path):
    """Create a non-ELF file."""
    path = tmp_path / "not_elf"
    path.write_bytes(b"This is not an ELF file")
    return str(path)
