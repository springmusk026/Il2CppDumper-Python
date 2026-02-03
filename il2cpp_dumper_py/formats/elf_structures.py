"""
ELF format structure definitions.
"""

from dataclasses import dataclass
from typing import List

# ELF Constants
ET_NONE = 0
ET_REL = 1
ET_EXEC = 2
ET_DYN = 3
ET_CORE = 4

EM_386 = 3
EM_ARM = 40
EM_X86_64 = 62
EM_AARCH64 = 183

PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_SHLIB = 5
PT_PHDR = 6
PT_TLS = 7

PF_X = 1
PF_W = 2
PF_R = 4

DT_NULL = 0
DT_NEEDED = 1
DT_PLTRELSZ = 2
DT_PLTGOT = 3
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_STRSZ = 10
DT_SYMENT = 11
DT_INIT = 12
DT_FINI = 13
DT_SONAME = 14
DT_RPATH = 15
DT_SYMBOLIC = 16
DT_REL = 17
DT_RELSZ = 18
DT_RELENT = 19
DT_PLTREL = 20
DT_DEBUG = 21
DT_TEXTREL = 22
DT_JMPREL = 23
DT_INIT_ARRAY = 25
DT_FINI_ARRAY = 26
DT_GNU_HASH = 0x6FFFFEF5

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_HASH = 5
SHT_DYNAMIC = 6
SHT_NOTE = 7
SHT_NOBITS = 8
SHT_REL = 9
SHT_SHLIB = 10
SHT_DYNSYM = 11
SHT_LOUSER = 0x80000000

# ELF32 relocation types
R_386_32 = 1
R_ARM_ABS32 = 2

# ELF64/AARCH64 relocation types
R_AARCH64_ABS64 = 257
R_AARCH64_RELATIVE = 1027

# ELF64/X86_64 relocation types
R_X86_64_64 = 1
R_X86_64_RELATIVE = 8


@dataclass
class Elf32_Ehdr:
    """ELF32 file header."""
    e_ident: bytes = b''  # 16 bytes
    e_type: int = 0
    e_machine: int = 0
    e_version: int = 0
    e_entry: int = 0
    e_phoff: int = 0
    e_shoff: int = 0
    e_flags: int = 0
    e_ehsize: int = 0
    e_phentsize: int = 0
    e_phnum: int = 0
    e_shentsize: int = 0
    e_shnum: int = 0
    e_shstrndx: int = 0


@dataclass
class Elf64_Ehdr:
    """ELF64 file header."""
    e_ident: bytes = b''  # 16 bytes
    e_type: int = 0
    e_machine: int = 0
    e_version: int = 0
    e_entry: int = 0
    e_phoff: int = 0
    e_shoff: int = 0
    e_flags: int = 0
    e_ehsize: int = 0
    e_phentsize: int = 0
    e_phnum: int = 0
    e_shentsize: int = 0
    e_shnum: int = 0
    e_shstrndx: int = 0


@dataclass
class Elf32_Phdr:
    """ELF32 program header."""
    p_type: int = 0
    p_offset: int = 0
    p_vaddr: int = 0
    p_paddr: int = 0
    p_filesz: int = 0
    p_memsz: int = 0
    p_flags: int = 0
    p_align: int = 0


@dataclass
class Elf64_Phdr:
    """ELF64 program header."""
    p_type: int = 0
    p_flags: int = 0
    p_offset: int = 0
    p_vaddr: int = 0
    p_paddr: int = 0
    p_filesz: int = 0
    p_memsz: int = 0
    p_align: int = 0


@dataclass
class Elf32_Shdr:
    """ELF32 section header."""
    sh_name: int = 0
    sh_type: int = 0
    sh_flags: int = 0
    sh_addr: int = 0
    sh_offset: int = 0
    sh_size: int = 0
    sh_link: int = 0
    sh_info: int = 0
    sh_addralign: int = 0
    sh_entsize: int = 0


@dataclass
class Elf64_Shdr:
    """ELF64 section header."""
    sh_name: int = 0
    sh_type: int = 0
    sh_flags: int = 0
    sh_addr: int = 0
    sh_offset: int = 0
    sh_size: int = 0
    sh_link: int = 0
    sh_info: int = 0
    sh_addralign: int = 0
    sh_entsize: int = 0


@dataclass
class Elf32_Dyn:
    """ELF32 dynamic entry."""
    d_tag: int = 0
    d_un: int = 0


@dataclass
class Elf64_Dyn:
    """ELF64 dynamic entry."""
    d_tag: int = 0
    d_un: int = 0


@dataclass
class Elf32_Sym:
    """ELF32 symbol."""
    st_name: int = 0
    st_value: int = 0
    st_size: int = 0
    st_info: int = 0
    st_other: int = 0
    st_shndx: int = 0


@dataclass
class Elf64_Sym:
    """ELF64 symbol."""
    st_name: int = 0
    st_info: int = 0
    st_other: int = 0
    st_shndx: int = 0
    st_value: int = 0
    st_size: int = 0


@dataclass
class Elf32_Rel:
    """ELF32 relocation."""
    r_offset: int = 0
    r_info: int = 0


@dataclass
class Elf64_Rel:
    """ELF64 relocation."""
    r_offset: int = 0
    r_info: int = 0


@dataclass
class Elf32_Rela:
    """ELF32 relocation with addend."""
    r_offset: int = 0
    r_info: int = 0
    r_addend: int = 0


@dataclass
class Elf64_Rela:
    """ELF64 relocation with addend."""
    r_offset: int = 0
    r_info: int = 0
    r_addend: int = 0
